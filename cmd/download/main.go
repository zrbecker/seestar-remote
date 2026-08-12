// Command download mirrors the Seestar image tree via SMB2 over the P2PTunnel, then
// re-walks the device and diffs against local to report completeness. Downloads are
// resume-safe: files already present at full size are skipped, and the walk reconnects
// after a dead session.
//
// Env: SEESTAR_EMAIL, SEESTAR_PASSWORD, SEESTAR_MODEL,
// SEESTAR_SN, SEESTAR_MASTER, OUTBASE (default ./seestar-archive), SHARE (default
// "EMMC Images"), ROOT
// (default "MyWorks"), SMB_USER (default Guest), SMB_PARALLEL (default 4), LIST_ONLY
// (set = enumerate and write the manifest, no download).
//
// Scope: TARGETS (comma-separated top-level dirs under ROOT; empty = all) and
// EXCLUDE_EXT (comma-separated extensions to skip; empty = none). Both apply to the
// download walk, the LIST_ONLY manifest and the verify re-walk, so the manifest and the
// completeness verdict describe the filtered scope, not the whole device.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/zrbecker/seestar-remote/internal/cli"
	"github.com/zrbecker/seestar-remote/kalay"
	"github.com/zrbecker/seestar-remote/seestar"
)

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			return n
		}
	}
	return def
}

// tunConn adapts a tunnel channel to net.Conn, buffering reads in a pump goroutine.
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

var (
	readChunk = int64(1 << 20)
	parallel  = envInt("SMB_PARALLEL", 4)
)

// Download scope: TARGETS names top-level directories under ROOT, EXCLUDE_EXT skips file
// types. Empty means no restriction.
var (
	targets    = commaSet(os.Getenv("TARGETS"), false)
	excludeExt = commaSet(os.Getenv("EXCLUDE_EXT"), true)
)

// commaSet parses a comma-separated value into a set, trimming blanks. When lower is set,
// entries are lowercased and given a leading dot, so ".MP4", "mp4" and ".mp4" match.
func commaSet(v string, lower bool) map[string]bool {
	out := map[string]bool{}
	for p := range strings.SplitSeq(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if lower {
			p = strings.ToLower(p)
			if !strings.HasPrefix(p, ".") {
				p = "." + p
			}
		}
		out[p] = true
	}
	return out
}

// inScope reports whether a device-relative path lies under one of TARGETS, comparing
// only the first path segment: an out-of-scope directory is never opened, so its subtree
// costs no ReadDir round-trips. A file directly under ROOT is its own first segment, so
// TARGETS also excludes stray top-level files.
func inScope(rel string) bool {
	if len(targets) == 0 || rel == "" {
		return true
	}
	top := rel
	if before, _, ok := strings.Cut(rel, "/"); ok {
		top = before
	}
	return targets[top]
}

// setStr renders a filter set in sorted order, or empty if the set has no entries.
func setStr(m map[string]bool, empty string) string {
	if len(m) == 0 {
		return empty
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// wantFile reports whether a file passes the EXCLUDE_EXT filter.
func wantFile(name string) bool {
	if len(excludeExt) == 0 {
		return true
	}
	return !excludeExt[strings.ToLower(filepath.Ext(name))]
}

// fetchFile downloads rpath to dest via parallel ReadAt streamed into a .part file, under
// progress-aware timeouts. Each worker holds one readChunk-sized buffer and writes it at
// the range's offset, so peak memory is parallel*readChunk regardless of file size.
func fetchFile(fs *smb2.Share, rpath, dest string, deadStart, stallGap, hardCap time.Duration) (int64, error) {
	rf, err := fs.Open(rpath)
	if err != nil {
		return 0, err
	}
	defer rf.Close()
	st, err := rf.Stat()
	if err != nil {
		return 0, err
	}
	size := st.Size()
	// O_TRUNC is required: a leftover .part may be longer than this file, and workers only
	// write the ranges they fetch, so a stale tail would survive into the renamed result.
	f, err := os.OpenFile(dest+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return 0, err
	}
	// abort discards the partial file. Unlinking while workers still hold the fd is safe:
	// their writes land in the unreachable inode, freed when they close it.
	abort := func(n int64, e error) (int64, error) {
		os.Remove(dest + ".part")
		return n, e
	}
	var done atomic.Int64
	jobs := make(chan int64, 256)
	var wg sync.WaitGroup
	var rerr error
	var rmu sync.Mutex
	for range parallel {
		wg.Go(func() {
			buf := make([]byte, readChunk)
			for off := range jobs {
				end := min(off+readChunk, size)
				n, e := rf.ReadAt(buf[:end-off], off)
				if n > 0 {
					if _, we := f.WriteAt(buf[:n], off); we != nil {
						rmu.Lock()
						if rerr == nil {
							rerr = we
						}
						rmu.Unlock()
						return
					}
				}
				// Counted only after the write lands, so done means bytes persisted.
				done.Add(int64(n))
				if e != nil && e != io.EOF {
					rmu.Lock()
					if rerr == nil {
						rerr = e
					}
					rmu.Unlock()
					return
				}
			}
		})
	}
	go func() {
		for off := int64(0); off < size; off += readChunk {
			jobs <- off
		}
		close(jobs)
	}()
	finished := make(chan struct{})
	// Closed after the last worker rather than on return: the timeout paths below abandon
	// the workers mid-write.
	go func() { wg.Wait(); f.Close(); close(finished) }()
	start, lastProg := time.Now(), time.Now()
	var lastDone int64
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-finished:
			rmu.Lock()
			e := rerr
			rmu.Unlock()
			if e != nil {
				return abort(done.Load(), e)
			}
			// A short ReadAt reports io.EOF, which workers do not treat as an error. WriteAt
			// past a gap makes the file sparse, so a missing range still yields a
			// full-length file that reads back as zeros. Commit only at the full byte count.
			if d := done.Load(); d != size {
				return abort(d, fmt.Errorf("short read: got %d of %d bytes", d, size))
			}
			return size, os.Rename(dest+".part", dest)
		case <-tick.C:
			d := done.Load()
			if d > lastDone {
				lastDone, lastProg = d, time.Now()
			}
			if d == 0 && time.Since(start) > deadStart {
				return abort(0, fmt.Errorf("dead session (0 bytes in %s)", deadStart))
			}
			if time.Since(lastProg) > stallGap {
				return abort(d, fmt.Errorf("full stall (%s no progress at %d/%d)", stallGap, d, size))
			}
			if time.Since(start) > hardCap {
				return abort(d, fmt.Errorf("hardcap %s at %d/%d", hardCap, d, size))
			}
		}
	}
}

// fetchWithTimeout bounds fetchFile with an absolute deadline, so a fetch wedged on a dead
// tunnel returns an error the caller can reconnect from instead of hanging.
func fetchWithTimeout(fs *smb2.Share, rpath, dest string, deadStart, stallGap, hardCap time.Duration) (int64, error) {
	type res struct {
		n int64
		e error
	}
	ch := make(chan res, 1)
	go func() {
		n, e := fetchFile(fs, rpath, dest, deadStart, stallGap, hardCap)
		ch <- res{n, e}
	}()
	select {
	case r := <-ch:
		return r.n, r.e
	case <-time.After(hardCap + 20*time.Second):
		return 0, fmt.Errorf("hard timeout %s (fetch wedged)", hardCap+20*time.Second)
	}
}

// readDirTimeout bounds an SMB ReadDir, turning a wedged listing into a recoverable error.
func readDirTimeout(fs *smb2.Share, path string, d time.Duration) ([]os.FileInfo, error) {
	type res struct {
		fi []os.FileInfo
		e  error
	}
	ch := make(chan res, 1)
	go func() { fi, e := fs.ReadDir(path); ch <- res{fi, e} }()
	select {
	case r := <-ch:
		return r.fi, r.e
	case <-time.After(d):
		return nil, fmt.Errorf("readdir timeout %s (wedged)", d)
	}
}

type fileEnt struct {
	rel  string // device-relative path under ROOT, forward slashes
	size int64
}

// walk recursively lists every in-scope file under root/rel into out.
func walk(fs *smb2.Share, root, rel string, out *[]fileEnt) error {
	devPath := root
	if rel != "" {
		devPath = root + "/" + rel
	}
	entries, err := fs.ReadDir(strings.ReplaceAll(devPath, "/", `\`))
	if err != nil {
		return fmt.Errorf("readdir %q: %w", devPath, err)
	}
	for _, e := range entries {
		n := e.Name()
		if n == "." || n == ".." {
			continue
		}
		childRel := n
		if rel != "" {
			childRel = rel + "/" + n
		}
		if e.IsDir() {
			if !inScope(childRel) {
				continue // pruned: not opened, so the subtree costs no round-trips
			}
			if err := walk(fs, root, childRel, out); err != nil {
				return err
			}
		} else {
			if !inScope(childRel) || !wantFile(n) {
				continue
			}
			*out = append(*out, fileEnt{rel: childRel, size: e.Size()})
		}
	}
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `download mirrors the Seestar's image archive over SMB2 through the Kalay P2P
tunnel, then re-walks the device and diffs to confirm nothing was missed.

Files already present locally at matching size are skipped, so a run resumes.

Usage:
  download [flags]

  OUTBASE=/path/to/archive download
  TARGETS="M 24,Mizar" EXCLUDE_EXT=".mp4,.avi" OUTBASE=/path/to/archive download

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Environment:
  OUTBASE
        Local archive root (default ./seestar-archive). A manifest is written to
        $OUTBASE/_device_manifest.tsv.
  SHARE
        SMB share name (default "EMMC Images").
  ROOT
        Path under the share to walk (default MyWorks).
  TARGETS
        Comma-separated top-level directories under ROOT. Empty means all.
        Directories outside the list are never opened. Matching is on whole path
        segments, so "M 24" does not pull in "M 24_sub".
  EXCLUDE_EXT
        Comma-separated file extensions to skip, e.g. ".mp4,.avi". Empty means none.
  LIST_ONLY
        Set to write the manifest and stop, without downloading.
  SMB_PARALLEL
        Concurrent range reads per file (default 4).
  SMB_USER
        SMB user (default Guest).
%s
`, cli.ConnectEnvUsage)
}

func main() {
	noPrompt := flag.Bool("no-prompt", false, "fail instead of prompting for anything unset")
	cli.ParseFlags(usage)
	cfg, err := cli.Resolve(cli.NoPrompt(*noPrompt))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	share := cli.EnvOr("SHARE", "EMMC Images")
	root := cli.EnvOr("ROOT", "MyWorks")
	if len(targets) > 0 || len(excludeExt) > 0 {
		fmt.Printf("scope: root=%s targets=%s exclude-ext=%s\n",
			root, setStr(targets, "<all>"), setStr(excludeExt, "<none>"))
	}
	outBase := cli.EnvOr("OUTBASE", "./seestar-archive")
	smbUser := cli.EnvOr("SMB_USER", "Guest")
	listOnly := os.Getenv("LIST_ONLY") != ""

	connect := func() (*smb2.Share, func(), error) {
		var tun *kalay.Tunnel
		var err error
		for range 6 {
			if tun, err = seestar.Dial(cfg, 4700); err == nil {
				break
			}
			time.Sleep(12 * time.Second)
		}
		if tun == nil {
			return nil, nil, fmt.Errorf("dial: %v", err)
		}
		type setupRes struct {
			fs   *smb2.Share
			sess *smb2.Session
			err  error
		}
		resCh := make(chan setupRes, 1)
		go func() {
			ch, e := tun.OpenChannel(445)
			if e != nil {
				resCh <- setupRes{err: fmt.Errorf("open 445: %v", e)}
				return
			}
			dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer dcancel()
			dl := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: smbUser}}
			sess, e := dl.DialContext(dctx, newTunConn(ch))
			if e != nil {
				resCh <- setupRes{err: fmt.Errorf("smb dial: %v", e)}
				return
			}
			fs, e := sess.Mount(share)
			if e != nil {
				sess.Logoff()
				resCh <- setupRes{err: fmt.Errorf("mount: %v", e)}
				return
			}
			resCh <- setupRes{fs: fs, sess: sess}
		}()
		select {
		case r := <-resCh:
			if r.err != nil {
				tun.Close()
				return nil, nil, r.err
			}
			// Graceful teardown with a force-close watchdog: Umount and Logoff send SMB
			// over the tunnel and block forever on a wedged one, so if they do not finish
			// in time the tunnel is force-closed, which drops the UDP socket and keepalive,
			// unblocks the stuck calls and releases the device's single session.
			fs, sess := r.fs, r.sess
			return r.fs, func() {
				done := make(chan struct{})
				go func() {
					fs.Umount()
					sess.Logoff()
					tun.Close()
					close(done)
				}()
				select {
				case <-done:
					fmt.Println("  close: graceful SMB teardown completed")
				case <-time.After(8 * time.Second):
					fmt.Println("  close: Umount/Logoff blocked >8s — force-closing tunnel to unblock them")
					tun.Close()
					select {
					case <-done:
						fmt.Println("  close: teardown unblocked and returned after force-close (session released)")
					case <-time.After(3 * time.Second):
						fmt.Println("  close: teardown goroutine still not returned after force-close; abandoning (socket already closed, so session IS released)")
					}
				}
			}, nil
		case <-time.After(35 * time.Second):
			tun.Close()
			return nil, nil, fmt.Errorf("smb setup timeout (device unresponsive)")
		}
	}

	// enumerate lists the full in-scope tree, retrying on connect or walk failure.
	enumerate := func() ([]fileEnt, error) {
		var lastErr error
		for attempt := range 6 {
			fs, closer, err := connect()
			if err != nil {
				lastErr = err
				fmt.Fprintf(os.Stderr, "  [enum connect attempt %d] %v; resting\n", attempt+1, err)
				time.Sleep(40 * time.Second)
				continue
			}
			var files []fileEnt
			err = walk(fs, root, "", &files)
			closer()
			if err != nil {
				lastErr = err
				fmt.Fprintf(os.Stderr, "  [enum walk attempt %d] %v; resting\n", attempt+1, err)
				time.Sleep(40 * time.Second)
				continue
			}
			return files, nil
		}
		return nil, lastErr
	}

	os.MkdirAll(outBase, 0755)
	manifestPath := outBase + "/_device_manifest.tsv"
	devPath := func(rel string) string {
		p := root
		if rel != "" {
			p = root + "/" + rel
		}
		return strings.ReplaceAll(p, "/", `\`)
	}
	writeManifest := func(fs []fileEnt) {
		if mf, e := os.Create(manifestPath); e == nil {
			for _, f := range fs {
				fmt.Fprintf(mf, "%s\t%d\n", f.rel, f.size)
			}
			mf.Close()
		}
	}

	if listOnly {
		fmt.Println("=== enumerating device tree under", root, "===")
		files, err := enumerate()
		if err != nil {
			fmt.Println("enumeration failed:", err)
			os.Exit(1)
		}
		sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
		var total int64
		for _, f := range files {
			total += f.size
		}
		fmt.Printf("device has %d files, %.2f GB total\n", len(files), float64(total)/1e9)
		writeManifest(files)
		fmt.Println("manifest ->", manifestPath)
		fmt.Println("LIST_ONLY set — done (no download).")
		return
	}

	// Streaming walk-and-download: each missing file is fetched as the walk discovers it,
	// with no manifest built up front. Resume is a per-file local presence check, so
	// re-walking after a reconnect is idempotent. The download is complete when a walk pass
	// finds nothing left to fetch.
	failCount := map[string]int{}
	const maxFails = 4
	errReconnect := fmt.Errorf("session ended; reconnect")
	var got int        // files downloaded in the current pass
	var pass []fileEnt // every file seen this pass

	var streamWalk func(fs *smb2.Share, rel string) error
	streamWalk = func(fs *smb2.Share, rel string) error {
		entries, err := readDirTimeout(fs, devPath(rel), 45*time.Second)
		if err != nil {
			return fmt.Errorf("readdir %q: %w", rel, err)
		}
		for _, e := range entries {
			name := e.Name()
			if name == "." || name == ".." {
				continue
			}
			child := name
			if rel != "" {
				child = rel + "/" + name
			}
			if e.IsDir() {
				if !inScope(child) {
					continue // pruned: not opened, so the subtree costs no round-trips
				}
				if err := streamWalk(fs, child); err != nil {
					return err
				}
				continue
			}
			if !inScope(child) || !wantFile(name) {
				continue
			}
			pass = append(pass, fileEnt{child, e.Size()})
			local := outBase + "/" + child
			if st, e2 := os.Stat(local); e2 == nil && st.Size() == e.Size() {
				continue
			}
			if failCount[child] >= maxFails {
				continue // given up; the final verify reports it missing
			}
			os.MkdirAll(filepath.Dir(local), 0755)
			fmt.Printf("  fetch %s (%.1f MB) ... ", child, float64(e.Size())/1e6)
			// hardCap scales with size so a fixed ceiling cannot kill a large file that is
			// still progressing: it allows a 400KB/s floor plus 90s slack. Genuine wedges
			// are caught by stallGap instead.
			hardCap := 90*time.Second + time.Duration(e.Size()/400_000)*time.Second
			n, derr := fetchWithTimeout(fs, devPath(child), local, 25*time.Second, 90*time.Second, hardCap)
			if derr != nil {
				failCount[child]++
				fmt.Printf("ERR %v (fail #%d)\n", derr, failCount[child])
				return errReconnect
			}
			fmt.Printf("ok %d bytes\n", n)
			got++
		}
		return nil
	}

	consecFail := 0
	for {
		fs, closer, err := connect()
		if err != nil {
			consecFail++
			rest := min(time.Duration(40+consecFail*20)*time.Second, 5*time.Minute)
			fmt.Printf("connect failed (%v); resting %s (giving the box a break)\n", err, rest)
			time.Sleep(rest)
			continue
		}
		got = 0
		pass = pass[:0]
		werr := streamWalk(fs, "")
		closer()
		if werr == nil {
			writeManifest(pass)
			consecFail = 0
			if got == 0 {
				break // a complete walk that downloaded nothing: everything present or given up
			}
			fmt.Printf("  --- pass complete: %d downloaded; re-walking for stragglers ---\n", got)
			continue
		}
		if got > 0 {
			consecFail = 0
		}
		fmt.Printf("  session ended (%v); reconnecting to resume\n", werr)
		time.Sleep(4 * time.Second)
	}

	// Verify: re-walk the device and diff against local.
	fmt.Println("=== downloads reported done — RE-WALKING device to verify completeness ===")
	verifyFiles, err := enumerate()
	if err != nil {
		fmt.Println("verify enumeration failed:", err, "- cannot confirm completeness")
		os.Exit(1)
	}
	var missing, mismatch []string
	for _, f := range verifyFiles {
		local := outBase + "/" + f.rel
		st, err := os.Stat(local)
		if err != nil {
			missing = append(missing, f.rel)
		} else if st.Size() != f.size {
			mismatch = append(mismatch, fmt.Sprintf("%s (local %d != device %d)", f.rel, st.Size(), f.size))
		}
	}
	fmt.Printf("device now reports %d files\n", len(verifyFiles))
	if len(missing) == 0 && len(mismatch) == 0 {
		fmt.Printf("VERIFIED COMPLETE: every one of the %d device files is present locally at matching size.\n", len(verifyFiles))
	} else {
		fmt.Printf("NOT COMPLETE: %d missing, %d size-mismatch\n", len(missing), len(mismatch))
		for _, m := range missing {
			fmt.Println("  MISSING:", m)
		}
		for _, m := range mismatch {
			fmt.Println("  MISMATCH:", m)
		}
		os.Exit(2)
	}
}
