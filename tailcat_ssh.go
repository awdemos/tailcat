// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin) && !ts_omit_ssh

package tailcat

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/creack/pty"
	ssh "github.com/tailscale/gliderssh"
	"github.com/u-root/u-root/pkg/termios"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// SupportsSSHServer reports whether the platform supports running the built-in
// auth-free SSH server.
func SupportsSSHServer() bool { return true }

// HandleTailscaleSSHConn handles an incoming TCP connection as an SSH session.
// Authentication is not required — the WireGuard tunnel provides identity.
// The connection is served using the gliderlabs/ssh library with a single
// ed25519 host key generated on first use in ~/.config/tailcat/ssh/.
//
// Two modes are supported: if the SSH client sends a command, it is executed
// via the user's shell with "-c"; otherwise an interactive login shell is
// started with a PTY.
func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	keys, err := getHostKeys()
	if err != nil {
		s.lb.logf("SSH host keys: %v", err)
		c.Close()
		return
	}
	srv := &ssh.Server{
		Handler:             sessionHandler,
		NoClientAuthHandler: func(ctx ssh.Context) error { return nil },
		ChannelHandlers:     map[string]ssh.ChannelHandler{"session": ssh.DefaultSessionHandler},
		RequestHandlers:     map[string]ssh.RequestHandler{},
		SubsystemHandlers:   map[string]ssh.SubsystemHandler{},
	}
	for _, k := range keys {
		srv.AddHostKey(k)
	}
	srv.HandleConn(c)
}

// sessionHandler handles a single SSH session (shell or exec).
func sessionHandler(sess ssh.Session) {
	u, err := user.Current()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "failed to get current user: %v\r\n", err)
		sess.Exit(1)
		return
	}

	shell := loginShell(u)
	rawCmd := sess.RawCommand()

	var args []string
	if rawCmd == "" {
		args = []string{shell, "-l"}
	} else {
		args = []string{shell, "-c", rawCmd}
	}

	cmd := exec.Command(args[0], args[1:]...)

	// Honor the process HOME so tests can use a clean, hermetic home directory
	// that won't source user login files (e.g. .bashrc that auto-attaches tmux).
	homeDir := u.HomeDir
	if v := os.Getenv("HOME"); v != "" {
		homeDir = v
	}
	cmd.Dir = homeDir

	cmd.Env = []string{
		"SHELL=" + shell,
		"USER=" + u.Username,
		"HOME=" + homeDir,
		"PATH=" + defaultPath(u),
	}
	for _, env := range sess.Environ() {
		if acceptEnvPair(env) {
			cmd.Env = append(cmd.Env, env)
		}
	}

	ptyReq, winCh, isPTY := sess.Pty()
	if isPTY {
		sess.DisablePTYEmulation()
		runWithPTY(sess, cmd, ptyReq, winCh)
	} else {
		runWithPipes(sess, cmd)
	}
}

// runWithPTY runs cmd attached to a pseudo-terminal.
func runWithPTY(sess ssh.Session, cmd *exec.Cmd, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "pty open: %v\r\n", err)
		sess.Exit(1)
		return
	}
	defer ptmx.Close()
	defer tty.Close()

	// Configure terminal modes from the SSH request.
	if rc, err := tty.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			tios, err := termios.GTTY(int(fd))
			if err != nil {
				return
			}
			tios.Row = int(ptyReq.Window.Height)
			tios.Col = int(ptyReq.Window.Width)
			for c, v := range ptyReq.Modes {
				if c == gossh.TTY_OP_ISPEED {
					tios.Ispeed = int(v)
					continue
				}
				if c == gossh.TTY_OP_OSPEED {
					tios.Ospeed = int(v)
					continue
				}
				k, ok := opcodeShortName[c]
				if !ok {
					continue
				}
				if _, ok := tios.CC[k]; ok {
					tios.CC[k] = uint8(v)
					continue
				}
				if _, ok := tios.Opts[k]; ok {
					tios.Opts[k] = v > 0
					continue
				}
			}
			tios.STTY(int(fd))
		})
	}

	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(sess.Stderr(), "start: %v\r\n", err)
		sess.Exit(1)
		return
	}
	// Child owns its own fd to the slave; close the parent's copy now so
	// the slave gets EOF once the child exits, and so we don't double-close
	// it in the deferred cleanup.
	tty.Close()
	tty = nil

	// Handle window size changes. We keep a duplicated fd to the pty
	// master so the window goroutine can outlive this function without
	// racing the deferred ptmx.Close. The goroutine is cancelled once the
	// command exits so the duplicated fd is released and the pty master
	// gets EOF, unblocking the stdout copy.
	winchCtx, winchCancel := context.WithCancel(context.Background())
	var winchWg sync.WaitGroup
	if winchFd, err := unix.Dup(int(ptmx.Fd())); err == nil {
		winchWg.Add(1)
		go func() {
			defer winchWg.Done()
			defer unix.Close(winchFd)
			for {
				select {
				case win, ok := <-winCh:
					if !ok {
						return
					}
					unix.IoctlSetWinsize(winchFd, syscall.TIOCSWINSZ, &unix.Winsize{
						Row:    uint16(win.Height),
						Col:    uint16(win.Width),
						Xpixel: uint16(win.WidthPixels),
						Ypixel: uint16(win.HeightPixels),
					})
				case <-winchCtx.Done():
					return
				}
			}
		}()
	}
	defer func() {
		winchCancel()
		winchWg.Wait()
	}()

	// I/O: session ↔ pty master.
	go func() {
		io.Copy(ptmx, sess) // stdin
	}()

	// Wait for the command to finish or for the stdout copy to finish
	// (e.g. the client disconnected). In the common case the command
	// exits first; we then cancel the window goroutine so its duplicated
	// pty-master fd is closed, allowing the stdout copy to drain EOF and
	// return. If the client goes away first, kill the shell.
	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		io.Copy(sess, ptmx) // stdout
	}()

	var waitErr error
	select {
	case waitErr = <-cmdDone:
		// Command exited. Release the window goroutine's fd so the
		// stdout copy gets EOF and returns.
		winchCancel()
		winchWg.Wait()
		<-stdoutDone
	case <-stdoutDone:
		// Client/session went away before the command exited.
		winchCancel()
		winchWg.Wait()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		waitErr = <-cmdDone
	}

	if waitErr != nil {
		sess.Exit(exitCode(waitErr))
		return
	}
	sess.Exit(0)
}

// runWithPipes runs cmd with stdin/stdout/stderr pipes (no PTY).
func runWithPipes(sess ssh.Session, cmd *exec.Cmd) {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "stdin pipe: %v\r\n", err)
		sess.Exit(1)
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "stdout pipe: %v\r\n", err)
		sess.Exit(1)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(sess.Stderr(), "stderr pipe: %v\r\n", err)
		sess.Exit(1)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(sess.Stderr(), "start: %v\r\n", err)
		sess.Exit(1)
		return
	}

	go func() {
		defer stdinPipe.Close()
		io.Copy(stdinPipe, sess)
	}()

	outputDone := make(chan struct{})
	var openStreams atomic.Int32
	openStreams.Store(2) // stdout + stderr
	closeOutput := func() {
		if openStreams.Add(-1) == 0 {
			close(outputDone)
		}
	}
	go func() {
		defer closeOutput()
		io.Copy(sess, stdoutPipe)
	}()
	go func() {
		defer closeOutput()
		io.Copy(sess.Stderr(), stderrPipe)
	}()

	// Drain stdout/stderr before calling Wait: Wait closes the pipes
	// once the process exits, racing the copies and sometimes losing
	// the output of fast-exiting commands. (The copies finish on
	// their own: the pipes read EOF when the process exits.)
	<-outputDone
	err = cmd.Wait()

	if err != nil {
		sess.Exit(exitCode(err))
		return
	}
	sess.Exit(0)
}

// exitCode extracts the exit code from an exec error.
func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

// acceptEnvPair reports whether the environment variable key=value pair
// should be accepted from the client (same default as OpenSSH AcceptEnv).
func acceptEnvPair(kv string) bool {
	k, _, ok := strings.Cut(kv, "=")
	if !ok {
		return false
	}
	return k == "TERM" || k == "LANG" || strings.HasPrefix(k, "LC_")
}

// loginShell returns the user's login shell.
func loginShell(u *user.User) string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("dscl", ".", "-read", filepath.Join("/Users", u.Username), "UserShell").Output()
		if err == nil {
			if s, ok := strings.CutPrefix(string(out), "UserShell: "); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/sh"
}

// defaultPath returns the default PATH for the given user.
func defaultPath(u *user.User) string {
	if u.Uid == "0" {
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

// getHostKeys returns the SSH host key signers, generating an ed25519 key
// in ~/.config/tailcat/ssh/ if one doesn't exist.
func getHostKeys() ([]gossh.Signer, error) {
	dir, err := sshKeyDir()
	if err != nil {
		return nil, err
	}
	keyPEM, err := hostKeyFileOrCreate(dir)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing host key: %w", err)
	}
	return []gossh.Signer{signer}, nil
}

func sshKeyDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("UserConfigDir: %w", err)
	}
	dir := filepath.Join(cfgDir, "tailcat", "ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// hostKeyMu protects concurrent generation of host keys with
// [getHostKeys], making sure two callers don't try to concurrently find
// a missing key and generate it at the same time, returning different keys to
// their callers.
var hostKeyMu sync.Mutex

func hostKeyFileOrCreate(keyDir string) ([]byte, error) {
	hostKeyMu.Lock()
	defer hostKeyMu.Unlock()

	path := filepath.Join(keyDir, "ssh_host_ed25519_key")
	v, err := os.ReadFile(path)
	if err == nil {
		return v, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, err
	}
	return pemData, nil
}

// opcodeShortName maps SSH terminal mode opcodes to mnemonic names
// expected by the termios package.
var opcodeShortName = map[uint8]string{
	gossh.VINTR:         "intr",
	gossh.VQUIT:         "quit",
	gossh.VERASE:        "erase",
	gossh.VKILL:         "kill",
	gossh.VEOF:          "eof",
	gossh.VEOL:          "eol",
	gossh.VEOL2:         "eol2",
	gossh.VSTART:        "start",
	gossh.VSTOP:         "stop",
	gossh.VSUSP:         "susp",
	gossh.VDSUSP:        "dsusp",
	gossh.VREPRINT:      "rprnt",
	gossh.VWERASE:       "werase",
	gossh.VLNEXT:        "lnext",
	gossh.VFLUSH:        "flush",
	gossh.VSWTCH:        "swtch",
	gossh.VSTATUS:       "status",
	gossh.VDISCARD:      "discard",
	gossh.IGNPAR:        "ignpar",
	gossh.PARMRK:        "parmrk",
	gossh.INPCK:         "inpck",
	gossh.ISTRIP:        "istrip",
	gossh.INLCR:         "inlcr",
	gossh.IGNCR:         "igncr",
	gossh.ICRNL:         "icrnl",
	gossh.IUCLC:         "iuclc",
	gossh.IXON:          "ixon",
	gossh.IXANY:         "ixany",
	gossh.IXOFF:         "ixoff",
	gossh.IMAXBEL:       "imaxbel",
	gossh.IUTF8:         "iutf8",
	gossh.ISIG:          "isig",
	gossh.ICANON:        "icanon",
	gossh.XCASE:         "xcase",
	gossh.ECHO:          "echo",
	gossh.ECHOE:         "echoe",
	gossh.ECHOK:         "echok",
	gossh.ECHONL:        "echonl",
	gossh.NOFLSH:        "noflsh",
	gossh.TOSTOP:        "tostop",
	gossh.IEXTEN:        "iexten",
	gossh.ECHOCTL:       "echoctl",
	gossh.ECHOKE:        "echoke",
	gossh.PENDIN:        "pendin",
	gossh.OPOST:         "opost",
	gossh.OLCUC:         "olcuc",
	gossh.ONLCR:         "onlcr",
	gossh.OCRNL:         "ocrnl",
	gossh.ONOCR:         "onocr",
	gossh.ONLRET:        "onlret",
	gossh.CS7:           "cs7",
	gossh.CS8:           "cs8",
	gossh.PARENB:        "parenb",
	gossh.PARODD:        "parodd",
	gossh.TTY_OP_ISPEED: "tty_op_ispeed",
	gossh.TTY_OP_OSPEED: "tty_op_ospeed",
}
