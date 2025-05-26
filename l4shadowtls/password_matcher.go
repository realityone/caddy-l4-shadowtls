package l4shadowtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

const (
	_tlsRandomSize    = 32
	_tlsHeaderSize    = 5
	_tlsSessionIDSize = 32

	_serverRandomIdx   = _tlsHeaderSize + 1 + 3 + 2
	_sessionIDLenIdx   = _tlsHeaderSize + 1 + 3 + 2 + _tlsRandomSize
	_tlsHmacHeaderSize = _tlsHeaderSize + _hmacSize

	_hmacSize = 4
)

func init() {
	caddy.RegisterModule(&MatchPassword{})
}

type MatchPassword struct {
	Password string `json:"password,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*MatchPassword) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "shadow_tls.handshake_match.password",
		New: func() caddy.Module { return new(MatchPassword) },
	}
}

func (m *MatchPassword) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

func (m *MatchPassword) Match(hello *tls.ClientHelloInfo) bool {
	cx, ok := hello.Conn.(*layer4.Connection)
	if !ok {
		m.logger.Error("failed to cast connection as *layer4.Connection", zap.String("conn", fmt.Sprintf("%T", hello.Conn)))
		return false
	}
	if !m.supportsTLS13(hello) {
		m.logger.Info("ignore this client hello because tls1.3 not supported")
		return false
	}
	helloBytes := cx.GetVar(ClientHelloBytesKey).([]byte)
	matchPassword := m.verifyShadowTLSClientHello(helloBytes, m.Password)
	m.logger.Debug("client hello result", zap.Bool("match_password", matchPassword))
	if matchPassword {
		cx.SetVar(ClientHelloPasswordKey, m.Password)
	}
	return matchPassword
}

func (m *MatchPassword) verifyShadowTLSClientHello(helloBytes []byte, password string) bool {
	const (
		_minLen  = _tlsHeaderSize + 1 + 3 + 2 + _tlsRandomSize + 1 + _tlsSessionIDSize
		_hmacIdx = _sessionIDLenIdx + 1 + _tlsSessionIDSize - _hmacSize
	)

	if len(helloBytes) < _minLen || helloBytes[_sessionIDLenIdx] != _tlsSessionIDSize {
		m.logger.Info("ignore this client hello because insufficient length or session id length mismatch")
		return false
	}

	h := hmac.New(sha1.New, []byte(password))
	h.Write(helloBytes[_tlsHeaderSize:_hmacIdx])
	h.Write([]byte{0, 0, 0, 0})
	h.Write(helloBytes[_hmacIdx+_hmacSize:])
	digest := h.Sum(nil)

	return bytes.Equal(digest[:_hmacSize], helloBytes[_hmacIdx:_hmacIdx+_hmacSize])
}

func (m *MatchPassword) supportsTLS13(hello *tls.ClientHelloInfo) bool {
	return slices.Contains(hello.SupportedVersions, tls.VersionTLS13)
}

// UnmarshalCaddyfile sets up the MatchALPN from Caddyfile tokens. Syntax:
//
//	alpn <values...>
func (m *MatchPassword) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		wrapper := d.Val()

		// Only one password is supported
		if d.CountRemainingArgs() != 1 {
			return d.ArgErr()
		}
		m.Password = d.RemainingArgs()[0]

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddytls.ConnectionMatcher = (*MatchPassword)(nil)
	_ caddyfile.Unmarshaler      = (*MatchPassword)(nil)
	_ caddy.Provisioner          = (*MatchPassword)(nil)
)
