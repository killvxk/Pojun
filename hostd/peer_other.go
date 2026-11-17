//go:build !linux

package hostd

import (
	"context"
	"fmt"
)

func (s *Server) checkPeer(context.Context) error {
	return fmt.Errorf("拒绝：当前系统不能核验 unix 对端进程")
}
