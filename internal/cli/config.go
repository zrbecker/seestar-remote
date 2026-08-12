// Package cli resolves a ConnectConfig from the environment, prompting for anything
// missing unless prompting is disabled.
package cli

import (
	"bufio"
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/zrbecker/seestar-remote/kalay"
	"github.com/zrbecker/seestar-remote/seestar"
)

// EnvOr returns the environment value for k, or def when unset.
func EnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// NoPrompt reports whether prompting is disabled, by flag or by SEESTAR_NO_PROMPT.
func NoPrompt(flag bool) bool { return flag || os.Getenv("SEESTAR_NO_PROMPT") != "" }

// Resolve builds a ConnectConfig. Credentials come from SEESTAR_EMAIL/SEESTAR_PASSWORD and
// the device from SEESTAR_SN/SEESTAR_MODEL; anything unset is prompted for, selecting the
// device from the account's list. With noPrompt set, a missing value is an error instead,
// so scripted runs fail rather than block. The returned config carries the access token, so
// Dial does not log in again.
func Resolve(noPrompt bool) (seestar.ConnectConfig, error) {
	var cfg seestar.ConnectConfig

	chRecord, err := clientHello()
	if err != nil {
		return cfg, err
	}

	email, password := os.Getenv("SEESTAR_EMAIL"), os.Getenv("SEESTAR_PASSWORD")
	if email == "" || password == "" {
		if noPrompt {
			return cfg, fmt.Errorf("SEESTAR_EMAIL and SEESTAR_PASSWORD must be set when prompting is disabled")
		}
		if email, err = ask("ZWO account email: "); err != nil {
			return cfg, err
		}
		if password, err = askSecret("Password: "); err != nil {
			return cfg, err
		}
	}

	token, err := seestar.Login(email, password)
	if err != nil {
		return cfg, err
	}

	sn, model := os.Getenv("SEESTAR_SN"), os.Getenv("SEESTAR_MODEL")
	if sn == "" {
		if sn, model, err = selectDevice(token, noPrompt); err != nil {
			return cfg, err
		}
	}
	if model == "" {
		model = "Seestar S30 Pro"
	}

	return seestar.ConnectConfig{
		Email:             email,
		Password:          password,
		Token:             token,
		DeviceModel:       model,
		DeviceSn:          sn,
		Master:            EnvOr("SEESTAR_MASTER", "119.45.181.137:3478"),
		ClientHelloRecord: chRecord,
	}, nil
}

// selectDevice lists the account's devices and returns the chosen serial and model. A sole
// device is taken without asking.
func selectDevice(token string, noPrompt bool) (sn, model string, err error) {
	devices, err := seestar.ListDevices(token, "")
	if err != nil {
		return "", "", err
	}
	switch len(devices) {
	case 0:
		return "", "", fmt.Errorf("no devices registered to this account")
	case 1:
		fmt.Fprintf(os.Stderr, "device: %s\n", devices[0].Label())
		return devices[0].Sn, devices[0].Model, nil
	}
	if noPrompt {
		var sns []string
		for _, d := range devices {
			sns = append(sns, d.Sn)
		}
		return "", "", fmt.Errorf("account has %d devices; set SEESTAR_SN to one of: %s",
			len(devices), strings.Join(sns, ", "))
	}
	for i, d := range devices {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, d.Label())
	}
	for {
		s, err := ask(fmt.Sprintf("Device [1-%d]: ", len(devices)))
		if err != nil {
			return "", "", err
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(s))
		if convErr == nil && n >= 1 && n <= len(devices) {
			return devices[n-1].Sn, devices[n-1].Model, nil
		}
		fmt.Fprintln(os.Stderr, "  not a listed choice")
	}
}

// embeddedClientHello is a captured DTLS 1.2 ClientHello, replayed during the handshake.
// It is a standard boringssl ClientHello with no device, account, or secret content, so it
// is a fixed product-wide constant. SEESTAR_CH overrides it with a file of the same 570-hex
// form.
//
//go:embed clienthello.hex
var embeddedClientHello string

// clientHello returns the DTLS ClientHello record to replay, from SEESTAR_CH if set,
// otherwise the embedded capture.
func clientHello() ([]byte, error) {
	chHex := embeddedClientHello
	src := "embedded ClientHello"
	if path := os.Getenv("SEESTAR_CH"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("SEESTAR_CH: %w", err)
		}
		chHex, src = string(b), "SEESTAR_CH ("+path+")"
	}
	if len(chHex) < 570 {
		return nil, fmt.Errorf("%s: need the 570-hex ClientHello record, got %d bytes", src, len(chHex))
	}
	wire, err := hex.DecodeString(chHex[:570])
	if err != nil {
		return nil, fmt.Errorf("%s: not valid hex: %w", src, err)
	}
	if len(wire) < 28 {
		return nil, fmt.Errorf("%s: decoded record too short (%d bytes, need >28)", src, len(wire))
	}
	return kalay.DecodePayloadData(wire)[28:], nil
}

// ask prompts on stderr and reads a line from stdin, so prompts stay out of piped stdout.
func ask(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// askSecret reads without echoing when stdin is a terminal, and falls back to a plain read
// when it is not (a pipe or here-doc).
func askSecret(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return ask(prompt)
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(b), nil
}

// ConnectEnvUsage documents the environment Resolve reads. Commands append their own.
const ConnectEnvUsage = `  SEESTAR_EMAIL, SEESTAR_PASSWORD
        ZWO account. Prompted for when unset.
  SEESTAR_SN
        Device serial. Chosen from the account's devices when unset.
  SEESTAR_MODEL
        Device model. Taken from the device list when unset.
  SEESTAR_MASTER
        Kalay rendezvous master (default 119.45.181.137:3478).
  SEESTAR_CH
        Override the embedded DTLS ClientHello with a 570-hex file (rarely needed).
  SEESTAR_NO_PROMPT
        Set to disable prompting, same as -no-prompt.
  KALAY_TUN_DEBUG
        Set for tunnel and RDT tracing on stderr.`

// ParseFlags parses the command line, printing usage for -h/--help and exiting 0. A
// genuine flag error prints usage and exits 2.
func ParseFlags(usage func()) {
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard) // suppress the package's own error/usage output
	flag.Usage = func() {}
	err := flag.CommandLine.Parse(os.Args[1:])
	if err == nil {
		return
	}
	flag.CommandLine.SetOutput(os.Stderr)
	usage()
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
	os.Exit(2)
}
