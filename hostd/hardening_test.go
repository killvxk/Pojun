package hostd

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRejectDowngrade(t *testing.T) {
	s := &Server{Version: "v0.4.80"}
	if err := s.rejectDowngrade("v0.4.1"); err == nil {
		t.Fatal("更低版本应被拒绝")
	}
	if err := s.rejectDowngrade("0.4.80"); err != nil {
		t.Fatal(err)
	}
	if err := s.rejectDowngrade("v0.4.81"); err != nil {
		t.Fatal(err)
	}
	dev := &Server{Version: "dev"}
	if err := dev.rejectDowngrade("v0.4.1"); err != nil {
		t.Fatal(err)
	}
}

func TestUnverifiedInstallBlockedUnlessOptIn(t *testing.T) {
	t.Setenv("POJUN_HOSTD_ALLOW_UNVERIFIED", "")
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	if _, err := s.Start(context.Background(), "nuclei", ""); err == nil {
		t.Fatal("未校验的 GitHub 配方应默认拒绝")
	}
	t.Setenv("POJUN_HOSTD_ALLOW_UNVERIFIED", "1")
	if _, err := s.Start(context.Background(), "does-not-exist", ""); err == nil {
		t.Fatal("未知工具仍应拒绝")
	}
}

func TestPeerAllowsConfiguredExecutableOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peer cred only on linux")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	good := NewServer(context.Background(), log.New(io.Discard, "", 0))
	good.RequirePeer = true
	good.AllowedExe = exe
	hs := &http.Server{
		Handler: good.Handler(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return WithPeerConn(ctx, c)
		},
	}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })

	client := http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}, Timeout: 5 * time.Second}
	resp, err := client.Get("http://hostd/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("配置的可执行文件应被允许，得到 %d", resp.StatusCode)
	}

	_ = hs.Close()
	_ = ln.Close()
	sock2 := filepath.Join(dir, "h2.sock")
	ln2, err := net.Listen("unix", sock2)
	if err != nil {
		t.Fatal(err)
	}
	bad := NewServer(context.Background(), log.New(io.Discard, "", 0))
	bad.RequirePeer = true
	bad.AllowedExe = "/bin/true"
	hs2 := &http.Server{
		Handler: bad.Handler(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return WithPeerConn(ctx, c)
		},
	}
	go func() { _ = hs2.Serve(ln2) }()
	t.Cleanup(func() {
		_ = hs2.Close()
		_ = ln2.Close()
	})
	client2 := http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock2)
		},
	}, Timeout: 5 * time.Second}
	resp, err = client2.Get("http://hostd/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("其他可执行文件应被拒绝，得到 %d", resp.StatusCode)
	}
}

func TestPIDFileNotTrustedWhenOwnedByCaller(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pid file ownership check is linux-specific")
	}
	path := filepath.Join(t.TempDir(), "pojun.pid")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootOwnedPID(path); err == nil {
		t.Fatal("非 root 拥有的 pid 文件不得作为 hostd 凭据")
	}
}
