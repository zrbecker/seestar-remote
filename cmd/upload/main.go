// Command upload writes local files into the Seestar's SMB image share over the Kalay P2P
// tunnel — the write-side counterpart to download. It creates any missing parent directories,
// streams each file in, and reads the size back to confirm the write. A directory argument
// uploads every file beneath it in one session, preserving structure.
//
// Usage:
//
//	upload <local_path> <device_rel_path>
//
// <device_rel_path> is relative to ROOT (default MyWorks), forward slashes, e.g.
// "finals/M31.fit" lands at MyWorks\finals\M31.fit in the "EMMC Images" share.
//
// Credentials and the device come from the environment; anything unset is prompted for.
// Env: SEESTAR_EMAIL, SEESTAR_PASSWORD, SEESTAR_SN, SEESTAR_MODEL, SEESTAR_MASTER,
// SHARE (default "EMMC Images"), ROOT (default "MyWorks"), SMB_USER (default Guest),
// UPLOAD_CHUNK (SMB write size, default 8192), UPLOAD_WORKERS (concurrent writers, default 16),
// SEESTAR_NO_PROMPT.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/zrbecker/seestar-remote/internal/cli"
	"github.com/zrbecker/seestar-remote/seestar"
)

// ---- tunnel channel as net.Conn (from download) ----
type tunConn struct {
	ch   io.ReadWriteCloser
	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
	rerr error
	rdl  time.Time
}

func newTunConn(ch io.ReadWriteCloser) *tunConn {
	c := &tunConn{ch: ch}
	c.cond = sync.NewCond(&c.mu)
	go c.pump()
	return c
}
func (c *tunConn) pump() {
	tmp := make([]byte, 65536)
	for {
		n, err := c.ch.Read(tmp)
		c.mu.Lock()
		if n > 0 {
			c.buf = append(c.buf, tmp[:n]...)
		}
		if err != nil {
			c.rerr = err
			c.cond.Broadcast()
			c.mu.Unlock()
			return
		}
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}
func (c *tunConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.buf) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if !c.rdl.IsZero() && time.Now().After(c.rdl) {
			return 0, os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		if !c.rdl.IsZero() {
			timer = time.AfterFunc(time.Until(c.rdl), func() { c.mu.Lock(); c.cond.Broadcast(); c.mu.Unlock() })
		}
		c.cond.Wait()
		if timer != nil {
			timer.Stop()
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}
func (c *tunConn) Write(p []byte) (int, error) { return c.ch.Write(p) }
func (c *tunConn) Close() error                { return c.ch.Close() }
func (c *tunConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}
func (c *tunConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *tunConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *tunConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *tunConn) RemoteAddr() net.Addr               { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tun" }
func (dummyAddr) String() string  { return "seestar:445" }

func usage() {
	fmt.Fprint(os.Stderr, `upload writes a local file into the Seestar's SMB image share over the Kalay P2P tunnel.

Usage:
  upload [flags] <local_path> <device_rel_path>

  <local_path> may be a file or a directory; a directory uploads every file beneath it in one
  session, preserving structure under <device_rel_path>.
  <device_rel_path> is relative to ROOT (default MyWorks), e.g. "finals/M31.fit".

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Environment:
  SHARE   SMB share name (default "EMMC Images")
  ROOT    path under the share to write beneath (default MyWorks)
  SMB_USER  SMB user (default Guest)
%s
`, cli.ConnectEnvUsage)
}

func main() {
	noPrompt := flag.Bool("no-prompt", false, "fail instead of prompting for anything unset")
	cli.ParseFlags(usage)
	if flag.NArg() != 2 {
		usage()
		os.Exit(2)
	}
	localPath := flag.Arg(0)
	relPath := strings.TrimLeft(path.Clean(strings.ReplaceAll(flag.Arg(1), `\`, "/")), "/")

	lst, err := os.Stat(localPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stat local:", err)
		os.Exit(1)
	}

	// Collect the files to upload with their device-relative destinations (forward slash, relative
	// to ROOT), all sent in one session. A single file maps to relPath as given; a directory uploads
	// every file beneath it, preserving structure under relPath — one session avoids the device's
	// per-session busy cooldown that many separate uploads would each pay.
	type item struct {
		local string
		rel   string
		size  int64
	}
	var items []item
	var totalBytes int64
	if lst.IsDir() {
		werr := filepath.WalkDir(localPath, func(p string, d os.DirEntry, e error) error {
			if e != nil || d.IsDir() {
				return e
			}
			fi, e := d.Info()
			if e != nil {
				return e
			}
			sub, e := filepath.Rel(localPath, p)
			if e != nil {
				return e
			}
			items = append(items, item{p, strings.TrimLeft(relPath+"/"+filepath.ToSlash(sub), "/"), fi.Size()})
			totalBytes += fi.Size()
			return nil
		})
		if werr != nil {
			fmt.Fprintln(os.Stderr, "walk local:", werr)
			os.Exit(1)
		}
		if len(items) == 0 {
			fmt.Fprintln(os.Stderr, "no files under", localPath)
			os.Exit(1)
		}
	} else {
		items = []item{{localPath, relPath, lst.Size()}}
		totalBytes = lst.Size()
	}

	cfg, err := cli.Resolve(cli.NoPrompt(*noPrompt))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	share := cli.EnvOr("SHARE", "EMMC Images")
	root := cli.EnvOr("ROOT", "MyWorks")
	smbUser := cli.EnvOr("SMB_USER", "Guest")
	fmt.Printf("upload: %d file(s), %.1f MB total -> \\\\%s\\%s\n", len(items), float64(totalBytes)/1e6, share, root)

	fmt.Println("dialing the device...")
	tun, err := seestar.Dial(cfg, 4700)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	ch, err := tun.OpenChannel(445)
	if err != nil {
		tun.Close()
		fmt.Fprintln(os.Stderr, "open 445:", err)
		os.Exit(1)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer dcancel()
	dl := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: smbUser}}
	sess, err := dl.DialContext(dctx, newTunConn(ch))
	if err != nil {
		tun.Close()
		fmt.Fprintln(os.Stderr, "smb dial:", err)
		os.Exit(1)
	}
	fs, err := sess.Mount(share)
	if err != nil {
		sess.Logoff()
		tun.Close()
		fmt.Fprintln(os.Stderr, "mount:", err)
		os.Exit(1)
	}

	// Graceful teardown with a force-close watchdog: Umount and Logoff send SMB over the
	// tunnel and block forever on a wedged one, so force-close the tunnel if they do not
	// finish in time, releasing the device's single session.
	defer func() {
		done := make(chan struct{})
		go func() { fs.Umount(); sess.Logoff(); tun.Close(); close(done) }()
		select {
		case <-done:
			fmt.Println("  close: graceful SMB teardown completed")
		case <-time.After(8 * time.Second):
			fmt.Println("  close: teardown blocked >8s — force-closing tunnel")
			tun.Close()
			<-time.After(2 * time.Second)
		}
	}()

	chunk := cli.EnvIntOr("UPLOAD_CHUNK", 8192)
	workers := cli.EnvIntOr("UPLOAD_WORKERS", 16)
	fmt.Printf("  chunk %d, %d workers\n", chunk, workers)

	start := time.Now()
	var done int64
	for i, it := range items {
		full := root
		if it.rel != "" {
			full = root + "/" + it.rel
		}
		if dir := path.Dir(full); dir != "." && dir != "/" {
			if err := mkdirP(fs, strings.ReplaceAll(dir, "/", `\`)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		winFull := strings.ReplaceAll(full, "/", `\`)
		t0 := time.Now()
		n, err := writeOneFile(fs, winFull, it.local, it.size, chunk, workers)
		done += n
		el := time.Since(t0).Seconds()
		rate := 0.0
		if el > 0 {
			rate = float64(n) / 1024 / el
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%d/%d] %s: %v\n", i+1, len(items), winFull, err)
			os.Exit(1)
		}
		fmt.Printf("[%d/%d] %s  %.1f MB  %.0fs  %.0f KB/s  (total %.0f/%.0f MB)\n",
			i+1, len(items), winFull, float64(n)/1e6, el, rate, float64(done)/1e6, float64(totalBytes)/1e6)
	}
	tot := time.Since(start).Seconds()
	avg := 0.0
	if tot > 0 {
		avg = float64(done) / 1024 / tot
	}
	fmt.Printf("done. %d file(s), %.1f MB in %.0fs (avg %.0f KB/s)\n", len(items), float64(done)/1e6, tot, avg)
}

// mkdirP creates winDir and any missing parents (Mkdir is not recursive), tolerating segments that
// already exist.
func mkdirP(fs *smb2.Share, winDir string) error {
	if winDir == "" || winDir == "." || winDir == `\` {
		return nil
	}
	var cur string
	for _, seg := range strings.Split(strings.ReplaceAll(winDir, `\`, "/"), "/") {
		if seg == "" {
			continue
		}
		if cur == "" {
			cur = seg
		} else {
			cur = cur + `\` + seg
		}
		if err := fs.Mkdir(cur, 0755); err != nil {
			if fi, e := fs.Stat(cur); e != nil || !fi.IsDir() {
				return fmt.Errorf("mkdir %q: %w", cur, err)
			}
		}
	}
	return nil
}

// writeOneFile streams localPath into winFull and verifies the device's reported size. It writes in
// chunks smaller than the tunnel's outbound send window, dispatched to a pool of concurrent WriteAt
// workers. Two things matter:
//  1. Chunk size. A single SMB WRITE PDU larger than the window deadlocks: the device will not ACK a
//     partial PDU (its SMB layer cannot consume until the whole PDU arrives), so the window fills and
//     never slides. Each chunk stays a self-contained sub-window PDU.
//  2. Concurrency. go-smb2's Write is synchronous — one PDU per round trip — so a serial loop is
//     RTT-bound. Independent WriteAt calls at distinct offsets keep several PDUs in flight, bounded
//     by the tunnel's send window, so throughput tracks window/RTT instead of chunk/RTT.
func writeOneFile(fs *smb2.Share, winFull, localPath string, expect int64, chunk, workers int) (int64, error) {
	lf, err := os.Open(localPath)
	if err != nil {
		return 0, err
	}
	defer lf.Close()
	wf, err := fs.Create(winFull)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", winFull, err)
	}
	type job struct {
		off int64
		b   []byte
	}
	jobs := make(chan job, workers*2)
	var n int64
	var writeErr error
	var errMu sync.Mutex
	var wg sync.WaitGroup

	// Periodic progress for large files, so a long transfer is visibly advancing rather than
	// indistinguishable from a stall. Reads the atomic byte counter every 15s.
	progressDone := make(chan struct{})
	if expect > 50<<20 {
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			start, last := time.Now(), int64(0)
			for {
				select {
				case <-progressDone:
					return
				case <-t.C:
					cur := atomic.LoadInt64(&n)
					inst := float64(cur-last) / 1024 / 15
					last = cur
					fmt.Printf("    %s: %.0f/%.0f MB (%.0f%%) %.0f KB/s, %.0fs elapsed\n",
						filepath.Base(winFull), float64(cur)/1e6, float64(expect)/1e6,
						100*float64(cur)/float64(expect), inst, time.Since(start).Seconds())
				}
			}
		}()
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				w, werr := wf.WriteAt(j.b, j.off)
				atomic.AddInt64(&n, int64(w))
				if werr != nil {
					errMu.Lock()
					if writeErr == nil {
						writeErr = werr
					}
					errMu.Unlock()
				}
			}
		}()
	}
	var off int64
	for {
		b := make([]byte, chunk)
		r, rerr := lf.Read(b)
		if r > 0 {
			jobs <- job{off, b[:r]}
			off += int64(r)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	close(jobs)
	wg.Wait()
	close(progressDone)
	if err == nil {
		err = writeErr
	}
	if cerr := wf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	fi, e := fs.Stat(winFull)
	if e != nil {
		return n, fmt.Errorf("post-stat failed: %w", e)
	}
	if fi.Size() != expect {
		return n, fmt.Errorf("size mismatch: wrote %d, device reports %d, expected %d", n, fi.Size(), expect)
	}
	return n, nil
}
