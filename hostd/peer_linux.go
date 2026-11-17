//go:build linux

package hostd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func (s *Server) checkPeer(ctx context.Context) error {
	c, _ := ctx.Value(peerConnKey{}).(net.Conn)
	if c == nil {
		return fmt.Errorf("拒绝：没有可核验的 unix 对端")
	}
	pid, err := peerPID(c)
	if err != nil {
		return fmt.Errorf("拒绝：无法读取对端进程")
	}
	exe, err := peerExe(pid)
	if err != nil {
		return fmt.Errorf("拒绝：无法解析对端可执行文件")
	}
	allowed := strings.TrimSpace(s.AllowedExe)
	if allowed == "" {
		return fmt.Errorf("拒绝：未配置允许的 pojun 主程序路径")
	}
	if resolved, err := filepath.EvalSymlinks(allowed); err == nil {
		allowed = resolved
	}
	if filepath.Clean(exe) != filepath.Clean(allowed) {
		return fmt.Errorf("拒绝：对端不是已配置的 pojun 主程序")
	}
	if strings.TrimSpace(s.AllowedPIDFile) != "" {
		want, err := readRootOwnedPID(s.AllowedPIDFile)
		if err != nil || want != pid {
			return fmt.Errorf("拒绝：对端进程与 root 登记的主进程不一致")
		}
	}
	return nil
}

func peerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("不是 unix 连接")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if gerr != nil {
		return 0, gerr
	}
	if cred == nil || cred.Pid <= 0 {
		return 0, fmt.Errorf("空凭据")
	}
	return int(cred.Pid), nil
}

func peerExe(pid int) (string, error) {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	p = strings.TrimSuffix(p, " (deleted)")
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return filepath.Clean(p), nil
}

// readRootOwnedPID 只接受 root 拥有、且所在目录也是 root 拥有并且都不可被
// 组或其他用户写入的 pid 文件。服务用户自己能改的文件不算凭据。
func readRootOwnedPID(path string) (int, error) {
	if err := rootOwnedImmutable(path); err != nil {
		return 0, err
	}
	if err := rootOwnedImmutable(filepath.Dir(path)); err != nil {
		return 0, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("pid 文件内容非法")
	}
	return n, nil
}

func rootOwnedImmutable(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return fmt.Errorf("%s 不是 root 所有", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s 可被属组或其他用户改写", path)
	}
	return nil
}
