package hostd

import (
	"context"
	"net"
)

type peerConnKey struct{}

// WithPeerConn 把接受连接放进请求上下文，供 SO_PEERCRED 核验。
func WithPeerConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, peerConnKey{}, c)
}

func (s *Server) authorizePeer(r interface{ Context() context.Context }) error {
	if s == nil || !s.RequirePeer {
		return nil
	}
	return s.checkPeer(r.Context())
}
