// Command proxy exposes device-local TCP ports as local listeners over the Kalay P2P tunnel.
//
// Ports are mapped Docker style, -p local:device, and may be given more than once. All
// mappings share one tunnel: the first is the tunnel's own channel and the rest are extra
// P2PTunnel channels within the same session, because the device rejects a second
// concurrent Kalay session.
//
// The tunnel is dialled once and held for the life of the process, so a client connection
// costs only a TCP accept. Running proxy occupies the device's single remote session until
// it exits. Each mapped port serves one client at a time.
//
// Useful device ports: 4700 JSON-RPC, 32323 ASCOM Alpaca REST, 80 HTTP image server.
//
// Credentials and the device come from the environment; anything unset is prompted for,
// choosing from the account's devices. -no-prompt (or SEESTAR_NO_PROMPT) makes a missing
// value an error instead.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/zrbecker/seestar-remote/internal/cli"
	"github.com/zrbecker/seestar-remote/seestar"
)

type mapping struct{ local, device int }

// mappings collects repeated -p local:device flags.
type mappings []mapping

func (m *mappings) String() string { return "" }

func (m *mappings) Set(v string) error {
	l, d, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("want local:device, got %q", v)
	}
	lp, err := strconv.Atoi(strings.TrimSpace(l))
	if err != nil || lp < 1 || lp > 65535 {
		return fmt.Errorf("bad local port in %q", v)
	}
	dp, err := strconv.Atoi(strings.TrimSpace(d))
	if err != nil || dp < 1 || dp > 65535 {
		return fmt.Errorf("bad device port in %q", v)
	}
	*m = append(*m, mapping{local: lp, device: dp})
	return nil
}

// forwarder carries one mapped port. A reader runs for the stream's lifetime, discarding
// output when no client is attached: the device pushes unsolicited data, which would
// otherwise queue and be delivered to whoever connected next.
type forwarder struct {
	m      mapping
	stream io.ReadWriteCloser

	mu     sync.Mutex
	client net.Conn
}

var errBusy = errors.New("another client is connected")

func (f *forwarder) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, err := f.stream.Read(buf)
		if n > 0 {
			f.mu.Lock()
			if f.client != nil {
				f.client.Write(buf[:n])
			}
			f.mu.Unlock()
		}
		if err != nil {
			f.mu.Lock()
			if f.client != nil {
				f.client.Close()
				f.client = nil
			}
			f.mu.Unlock()
			fmt.Printf("  device :%d stream closed: %v\n", f.m.device, err)
			return
		}
	}
}

func (f *forwarder) serve(conn net.Conn) {
	f.mu.Lock()
	if f.client != nil {
		f.mu.Unlock()
		replyError(conn, f.m.device, errBusy)
		conn.Close()
		return
	}
	f.client = conn
	f.mu.Unlock()

	io.Copy(f.stream, conn)

	f.mu.Lock()
	if f.client == conn {
		f.client = nil
	}
	f.mu.Unlock()
	conn.Close()
}

func (f *forwarder) start(ln net.Listener) {
	go f.readLoop()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Printf("client %s -> device :%d\n", conn.RemoteAddr(), f.m.device)
			go f.serve(conn)
		}
	}()
	fmt.Printf("  %-21s -> device :%d\n", ln.Addr(), f.m.device)
}

// replyError reports a failure to the client, which would otherwise see only an empty
// close. Port 4700 speaks newline-delimited JSON-RPC, so the reply matches that; other
// ports get a plain-text line rather than a reply in a protocol they do not speak.
func replyError(w io.Writer, port int, err error) {
	if port != 4700 {
		fmt.Fprintf(w, "proxy: %v\r\n", err)
		return
	}
	type rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	b, mErr := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		Error   rpcErr `json:"error"`
		ID      any    `json:"id"`
	}{JSONRPC: "2.0", Error: rpcErr{Code: -32000, Message: "proxy: " + err.Error()}})
	if mErr != nil {
		return
	}
	w.Write(append(b, '\r', '\n'))
}

func usage() {
	fmt.Fprint(os.Stderr, `proxy exposes device-local TCP ports as local listeners over the Kalay P2P tunnel.

Ports are mapped Docker style, -p local:device, repeatable. All mappings share one
tunnel, since the device rejects a second concurrent Kalay session. The tunnel is held
until the process exits, so each client connection costs only a TCP accept, and running
proxy occupies the device's single remote session. One client at a time per mapped port.

Device ports: 4700 JSON-RPC, 32323 ASCOM Alpaca REST, 80 HTTP image server.

Usage:
  proxy [flags]

  proxy -p 4700:4700
  proxy -p 32323:32323 -p 8080:80
  curl http://127.0.0.1:32323/management/apiversions

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Environment:
  LISTEN_HOST
        Address to bind the listeners to (default 127.0.0.1).
%s
`, cli.ConnectEnvUsage)
}

func main() {
	var maps mappings
	flag.Var(&maps, "p", "port mapping local:device, repeatable (default 4700:4700)")
	noPrompt := flag.Bool("no-prompt", false, "fail instead of prompting for anything unset")
	cli.ParseFlags(usage)
	if len(maps) == 0 {
		maps = mappings{{local: 4700, device: 4700}}
	}

	cfg, err := cli.Resolve(cli.NoPrompt(*noPrompt))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Bind before dialling: a port clash then costs nothing, where dialling first would
	// burn the device's single session before discovering it.
	host := cli.EnvOr("LISTEN_HOST", "127.0.0.1")
	lns := make([]net.Listener, len(maps))
	for i, m := range maps {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, m.local))
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			for _, prev := range lns[:i] {
				prev.Close()
			}
			os.Exit(1)
		}
		lns[i] = ln
	}

	fmt.Printf("proxy: %s (%s)\n", cfg.DeviceSn, cfg.DeviceModel)
	fmt.Printf("dialing the device (%d port%s)...\n", len(maps), map[bool]string{true: "", false: "s"}[len(maps) == 1])

	// The first mapping rides the tunnel's own channel; the rest are extra channels in the
	// same session.
	tun, err := seestar.Dial(cfg, maps[0].device)
	if err != nil {
		fmt.Fprintln(os.Stderr, "  dial failed:", err)
		os.Exit(1)
	}
	fwds := []*forwarder{{m: maps[0], stream: tun}}
	for _, m := range maps[1:] {
		ch, err := tun.OpenChannel(m.device)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  open channel to :%d: %v\n", m.device, err)
			tun.Close()
			os.Exit(1)
		}
		fwds = append(fwds, &forwarder{m: m, stream: ch})
	}
	fmt.Println("  tunnel up; holding it for the life of the process")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nreleasing the device session")
		tun.Close()
		os.Exit(0)
	}()

	for i, f := range fwds {
		f.start(lns[i])
	}
	select {}
}
