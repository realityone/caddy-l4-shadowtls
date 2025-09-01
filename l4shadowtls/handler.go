package l4shadowtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func init() {
	caddy.RegisterModule(&ShadowTLSHandler{})
}

const (
	_alert           = 0x15
	_applicationData = 0x17

	_tlsMajor              = 0x3
	_tlsMinor0, _tlsMinor1 = 0x03, 0x01
)

// Handler is a handler that can proxy connections.
type ShadowTLSHandler struct {
	HandshakeUpstream *Upstream `json:"handshake_upstream,omitempty"`
	DataUpstream      *Upstream `json:"data_upstream,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*ShadowTLSHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.shadow_tls",
		New: func() caddy.Module { return new(ShadowTLSHandler) },
	}
}

// Provision sets up the handler.
func (h *ShadowTLSHandler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)

	if h.HandshakeUpstream == nil {
		return fmt.Errorf("handshake_upstream is required")
	}
	if h.DataUpstream == nil {
		return fmt.Errorf("data_upstream is required")
	}
	if err := h.HandshakeUpstream.provision(ctx, h); err != nil {
		return fmt.Errorf("handshake_upstream: %v", err)
	}
	if err := h.DataUpstream.provision(ctx, h); err != nil {
		return fmt.Errorf("data_upstream: %v", err)
	}
	return nil
}

// Handle handles the downstream connection.
func (h *ShadowTLSHandler) Handle(down *layer4.Connection, next layer4.Handler) error {
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	clientHello, ok := down.GetVar(ClientHelloInfoKey).(ClientHelloInfo)
	if !ok {
		return fmt.Errorf("no tls client hello found")
	}

	handshakeConn, err := h.dialHandshakePeer(repl, down, clientHello)
	if err != nil {
		return err
	}
	defer handshakeConn.Close()

	// drain the first client hello frame.
	if _, err := readTLSFrame(down); err != nil {
		h.logger.Error("failed to drain client hello frame", zap.Error(err))
		return err
	}
	h.proxy(down, handshakeConn)
	return nil
}

func readTLSFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}

	length := int(uint16(hdr[3])<<8 | uint16(hdr[4])) // ignoring version in hdr[1:3] - like https://github.com/inetaf/tcpproxy/blob/master/sni.go#L170
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	frame := slices.Concat(hdr, body)
	return frame, nil
}

func parseServerHelloBytes(helloBytes []byte) (*serverHelloMsg, error) {
	const recordTypeHandshake = 0x16
	if helloBytes[0] != recordTypeHandshake {
		return nil, fmt.Errorf("expected handshake record type %d, got %d", recordTypeHandshake, helloBytes[0])
	}

	rawHello := helloBytes[_tlsHeaderSize:]
	serverHello, err := parseRawServerHello(rawHello)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server hello: %v", err)
	}
	return serverHello, nil
}

func (h *ShadowTLSHandler) proxy(down *layer4.Connection, handshakeConn net.Conn) {
	password, ok := down.GetVar(ClientHelloPasswordKey).(string)
	if !ok {
		h.logger.Error("cannot find client hello password in context")
		return
	}

	helloBytes, ok := down.GetVar(ClientHelloBytesKey).([]byte)
	if !ok {
		h.logger.Error("no tls client hello bytes found")
		return
	}
	if _, err := handshakeConn.Write(helloBytes); err != nil {
		h.logger.Error("failed to write client hello to handshake connection",
			zap.Error(err))
		return
	}

	firstServerFrame, err := readTLSFrame(handshakeConn)
	if err != nil {
		h.logger.Error("failed to read first server frame",
			zap.Error(err))
		return
	}
	h.logger.Debug("wrote first server hello to downstream connection")
	if _, err := down.Write(firstServerFrame); err != nil {
		h.logger.Error("failed to write first server hello to downstream",
			zap.Error(err))
		return
	}

	serverHello, err := parseServerHelloBytes(firstServerFrame)
	if err != nil {
		h.logger.Error("failed to read server hello", zap.Error(err))
		h.bidirectionalProxy(down, handshakeConn)
		return
	}
	serverRandom := serverHello.random
	h.logger.Debug("got server random", zap.String("handshake_conn", handshakeConn.RemoteAddr().String()), zap.String("server_random", hex.EncodeToString(serverRandom)))

	if serverHello.supportedVersion != tls.VersionTLS13 {
		h.logger.Error("this handshake server does not support TLS 1.3", zap.String("handshake_conn", handshakeConn.RemoteAddr().String()))
		h.bidirectionalProxy(down, handshakeConn)
		return
	}

	hmacSRC := newShortHMAC(password, [2][]byte{serverRandom, []byte("C")})
	hmacSR := newShortHMAC(password, [2][]byte{serverRandom, {}})
	key := kdf(password, serverRandom)

	var pureData []byte
	eg := errgroup.Group{}
	verifyCtx, verifyCancel := context.WithCancel(down.Context)
	eg.Go(func() error {
		defer verifyCancel()
		data, err := copyByFrameUntilHmacMatches(down, handshakeConn, hmacSRC)
		if err != nil {
			h.logger.Error("failed to copy by frame until hmac matches", zap.Error(err))
			return err
		}
		pureData = data
		return nil
	})
	eg.Go(func() error {
		if err := copyByFrameWithModification(verifyCtx, handshakeConn, down, hmacSR, key); err != nil {
			h.logger.Debug("failed to copy by frame with modification", zap.Error(err))
			return nil
		}
		return nil
	})
	eg.Go(func() error {
		<-verifyCtx.Done()
		_ = handshakeConn.Close()
		return nil
	})
	if err := eg.Wait(); err != nil {
		h.logger.Error("failed to relay handshake", zap.Error(err))
		return
	}

	dataConn, err := h.dialDataPeer(down)
	if err != nil {
		return
	}
	defer dataConn.Close()
	if _, err := dataConn.Write(pureData); err != nil {
		h.logger.Error("failed to write pure data to data peer", zap.Error(err))
		return
	}

	hmacSRS := newShortHMAC(password, [2][]byte{serverRandom, []byte("S")})

	vr := &verifiedRelay{
		ShadowTLSHandler: h,
	}
	vr.ctx, vr.cancel = context.WithCancel(down.Context)
	vr.verifiedRelay(dataConn, down, hmacSRS, hmacSRC)
}

type verifiedRelay struct {
	*ShadowTLSHandler

	ctx    context.Context
	cancel context.CancelFunc
}

func (h *verifiedRelay) verifiedRelay(dataConn net.Conn, down *layer4.Connection, hmacAdd ShortHMAC, hmacVerify ShortHMAC) {
	eg := errgroup.Group{}
	eg.Go(func() error {
		defer h.cancel()
		if err := copyRemoveAppdataAndVerify(h.ctx, down, dataConn, hmacVerify); err != nil {
			h.logger.Debug("failed to copy remove appdata and verify", zap.Error(err))
			return nil
		}
		return nil
	})
	eg.Go(func() error {
		defer h.cancel()
		if err := copyAddAppdata(h.ctx, dataConn, down, hmacAdd); err != nil {
			h.logger.Debug("failed to copy add appdata", zap.Error(err))
			return nil
		}
		return nil
	})
	eg.Go(func() error {
		<-h.ctx.Done()
		cw, ok := dataConn.(closeWriter)
		if ok {
			_ = cw.CloseWrite()
		} else {
			dataConn.Close()
		}
		_ = down.Close()
		return nil
	})
	if err := eg.Wait(); err != nil {
		h.logger.Error("failed to relay verified connection data", zap.Error(err))
	}
}

type TLSFrameReader interface {
	NextTLSFrame() ([]byte, error)
}

const _initBufferSize = 2048

type tlsFrameReader struct {
	r      io.Reader
	buffer []byte
}

func (r *tlsFrameReader) NextTLSFrame() ([]byte, error) {
	hdr := r.buffer[:_tlsHeaderSize]
	if _, err := io.ReadFull(r.r, hdr); err != nil {
		return nil, err
	}

	length := int(uint16(hdr[3])<<8 | uint16(hdr[4]))
	if length > len(r.buffer)-_tlsHeaderSize {
		r.buffer = slices.Grow(r.buffer, length-(len(r.buffer)-_tlsHeaderSize))
	}
	body := r.buffer[_tlsHeaderSize : _tlsHeaderSize+length]
	n, err := io.ReadFull(r.r, body)
	if err != nil {
		if errors.Is(err, io.EOF) {
			if n == length {
				return r.buffer[:_tlsHeaderSize+length], nil
			}
			return nil, io.EOF
		}
		return nil, err
	}
	return r.buffer[:_tlsHeaderSize+length], nil
}

// relay downstream to data server, remove application data and verify hmac
func copyRemoveAppdataAndVerify(ctx context.Context, downReader io.Reader, dataWriter io.Writer, hVerify ShortHMAC) error {
	tlsReader := &tlsFrameReader{
		r:      downReader,
		buffer: make([]byte, _initBufferSize),
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			frame, err := tlsReader.NextTLSFrame()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}

			switch frame[0] {
			case _alert:
				return fmt.Errorf("exit because alert frame received")
			case _applicationData:
				if !verifyAppdata(frame, hVerify, true) {
					return fmt.Errorf("exit because hmac verification failed")
				}
				if _, err := dataWriter.Write(frame[_tlsHmacHeaderSize:]); err != nil {
					return err
				}
			default:
				return fmt.Errorf("exit because unknown frame type received: %d", frame[0])
			}
		}
	}
}

func verifyAppdata(frame []byte, hVerify ShortHMAC, sep bool) bool {
	if frame[1] != _tlsMajor ||
		frame[2] != _tlsMinor0 ||
		len(frame) < _tlsHmacHeaderSize {
		return false
	}

	hVerify.Write(frame[_tlsHmacHeaderSize:])
	expectedDigest := hVerify.ShortDigest()
	if sep {
		hVerify.Write(expectedDigest[:])
	}

	return bytes.Equal(frame[_tlsHeaderSize:_tlsHmacHeaderSize], expectedDigest[:])
}

// relay data server to downstream, pack as tls application data frame
func copyAddAppdata(ctx context.Context, dataReader io.Reader, downWriter io.Writer, hmacAdd ShortHMAC) error {
	const _bufferSize = 4096
	var _defaultHeader = [_tlsHmacHeaderSize]byte{_applicationData, _tlsMajor, _tlsMinor0, 0, 0, 0, 0, 0, 0}

	buffer := make([]byte, _bufferSize)
	copy(buffer[:_tlsHmacHeaderSize], _defaultHeader[:])

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			frameLen, err := dataReader.Read(buffer[_tlsHmacHeaderSize:])
			processData := func() error {
				binary.BigEndian.PutUint16(buffer[3:5], uint16(frameLen+_hmacSize))

				hmacAdd.Write(buffer[_tlsHmacHeaderSize : _tlsHmacHeaderSize+frameLen])
				digest := hmacAdd.ShortDigest()
				hmacAdd.Write(digest[:])
				copy(buffer[_tlsHeaderSize:_tlsHeaderSize+_hmacSize], digest[:])

				if _, err := downWriter.Write(buffer[:_tlsHmacHeaderSize+frameLen]); err != nil {
					return err
				}
				return nil
			}
			if frameLen > 0 {
				if err := processData(); err != nil {
					return err
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
}

func copyByFrameUntilHmacMatches(downReader io.Reader, handshakeWriter io.Writer, h ShortHMAC) ([]byte, error) {
	const _tlsHmacHeaderSize = 9

	for {
		frame, err := readTLSFrame(downReader)
		if err != nil {
			return nil, err
		}

		if len(frame) > 9 && frame[0] == _applicationData {
			h0 := h.Clone()
			h0.Write(frame[_tlsHmacHeaderSize:])
			digest := h0.ShortDigest()

			if bytes.Equal(frame[_tlsHeaderSize:_tlsHmacHeaderSize], digest[:]) {
				h.Write(frame[_tlsHmacHeaderSize:])
				h.Write(frame[_tlsHeaderSize:_tlsHmacHeaderSize])
				return frame[_tlsHmacHeaderSize:], nil
			}
		}

		if _, err := handshakeWriter.Write(frame); err != nil {
			return nil, err
		}
	}
}
func copyByFrameWithModification(ctx context.Context, handshakeReader io.Reader, downWriter io.Writer, h ShortHMAC, key []byte) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		frame, err := readTLSFrame(handshakeReader)
		if err != nil {
			return err
		}

		if frame[0] == _applicationData {
			xorSlice(frame[_tlsHeaderSize:], key)
			h.Write(frame[_tlsHeaderSize:])
			digest := h.ShortDigest()
			frame = slices.Concat(frame, digest[:])

			copy(frame[_tlsHmacHeaderSize:], frame[_tlsHeaderSize:len(frame)-_hmacSize])
			copy(frame[_tlsHeaderSize:_tlsHeaderSize+_hmacSize], digest[:])

			dataSize := binary.BigEndian.Uint16(frame[3:5])
			dataSize += _hmacSize
			binary.BigEndian.PutUint16(frame[3:5], dataSize)
		}

		if _, err := downWriter.Write(frame); err != nil {
			return err
		}
	}
}

func kdf(password string, serverRandom []byte) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(serverRandom)
	return h.Sum(nil)
}

func xorSlice(data []byte, key []byte) {
	for i, b := range data {
		data[i] = b ^ key[i%len(key)]
	}
}

func (h *ShadowTLSHandler) dialHandshakePeer(repl *caddy.Replacer, down *layer4.Connection, clientHello ClientHelloInfo) (net.Conn, error) {
	var handshakePeer *peer
	for _, p := range h.HandshakeUpstream.peers {
		hostName := repl.ReplaceAll(p.address.Host, "")
		if hostName == clientHello.ServerName {
			handshakePeer = p
			break
		}
	}
	if handshakePeer == nil {
		return nil, fmt.Errorf("no handshake peer found for server name: %s", clientHello.ServerName)
	}

	addr := handshakePeer.address
	if addr.StartPort == 0 && addr.EndPort == 0 {
		addr.StartPort = 443
		addr.EndPort = 443
	}

	hostPort := repl.ReplaceAll(addr.JoinHostPort(0), "")
	handshakeConn, err := net.Dial(handshakePeer.address.Network, hostPort)
	if err != nil {
		h.logger.Error("failed to dial handshake peer",
			zap.String("remote", down.RemoteAddr().String()),
			zap.String("handshake_server", hostPort),
			zap.Error(err))
		return nil, err
	}
	h.logger.Debug("dial handshake peer",
		zap.String("remote", down.RemoteAddr().String()),
		zap.String("handshake_server", hostPort),
		zap.String("handshake_conn", handshakeConn.RemoteAddr().String()))
	return handshakeConn, nil
}

func (h *ShadowTLSHandler) dialDataPeer(down *layer4.Connection) (net.Conn, error) {
	var dataPeer *peer
	for _, p := range h.DataUpstream.peers {
		dataPeer = p
		break
	}
	if dataPeer == nil {
		return nil, fmt.Errorf("no data peer found")
	}

	addr := dataPeer.address
	hostPort := addr.JoinHostPort(0)
	dataConn, err := net.Dial(dataPeer.address.Network, hostPort)
	if err != nil {
		h.logger.Error("failed to dial data peer",
			zap.String("remote", down.RemoteAddr().String()),
			zap.String("data_server", hostPort),
			zap.Error(err))
		return nil, err
	}
	h.logger.Debug("dial data peer",
		zap.String("remote", down.RemoteAddr().String()),
		zap.String("data_server", hostPort),
		zap.String("data_conn", dataConn.RemoteAddr().String()))
	return dataConn, nil
}

func (h *ShadowTLSHandler) bidirectionalProxy(down *layer4.Connection, up net.Conn) {
	// every time we read from downstream, we write
	// the same to each upstream; this is half of
	// the proxy duplex
	var downTee io.Reader = down
	downTee = io.TeeReader(downTee, up)

	var wg sync.WaitGroup
	var downClosed atomic.Bool

	wg.Add(1)

	go func(up net.Conn) {
		defer wg.Done()

		if _, err := io.Copy(down, up); err != nil {
			// If the downstream connection has been closed, we can assume this is
			// the reason io.Copy() errored.  That's normal operation for UDP
			// connections after idle timeout, so don't log an error in that case.
			if !downClosed.Load() {
				h.logger.Error("upstream connection",
					zap.String("local_address", up.LocalAddr().String()),
					zap.String("remote_address", up.RemoteAddr().String()),
					zap.Error(err),
				)
			}
		}
	}(up)

	downConnClosedCh := make(chan struct{}, 1)

	go func() {
		// read from downstream until connection is closed;
		// TODO: this pumps the reader, but writing into discard is a weird way to do it; could be avoided if we used io.Pipe - see _gitignore/oldtee.go.txt
		_, _ = io.Copy(io.Discard, downTee)
		downConnClosedCh <- struct{}{}

		// Shut down the writing side of all upstream connections, in case
		// that the downstream connection is half closed. (issue #40)
		//
		// UDP connections meanwhile don't implement CloseWrite(), but in order
		// to ensure io.Copy() in the per-upstream goroutines (above) returns,
		// we need to close the socket.  This will cause io.Copy() return an
		// error, which in this particular case is expected, so we signal the
		// intentional closure by setting this flag.
		downClosed.Store(true)
		if conn, ok := up.(closeWriter); ok {
			_ = conn.CloseWrite()
		} else {
			_ = up.Close()
		}
	}()

	// wait for reading from all upstream connections
	wg.Wait()

	// Shut down the writing side of the downstream connection, in case that
	// the upstream connections are all half closed.
	if downConn, ok := down.Conn.(closeWriter); ok {
		_ = downConn.CloseWrite()
	}

	// Wait for reading from the downstream connection, if possible.
	<-downConnClosedCh
}

func (h *ShadowTLSHandler) Cleanup() error {
	// remove hosts from our config from the pool
	for _, dialAddr := range h.HandshakeUpstream.Dial {
		_, _ = peers.Delete(dialAddr)
	}
	for _, dialAddr := range h.DataUpstream.Dial {
		_, _ = peers.Delete(dialAddr)
	}
	return nil
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	shadow_tls {
//		handshake_server <server>
//		data_server <server>
//	}
func (h *ShadowTLSHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// Consume all same-line options
	for d.NextArg() {
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "handshake_server":
			u := &Upstream{}
			if err := u.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			h.HandshakeUpstream = u
		case "data_server":
			u := &Upstream{}
			if err := u.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
			h.DataUpstream = u
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	if h.HandshakeUpstream == nil {
		u := &Upstream{
			Dial: []string{"{l4.shadow_tls.server_name}"},
		}
		h.HandshakeUpstream = u
	}

	return nil
}

// peers is the global repository for peers that are
// currently in use by active configuration(s). This
// allows the state of remote hosts to be preserved
// through config reloads.
var peers = caddy.NewUsagePool()

// Interface guards
var (
	_ caddy.CleanerUpper    = (*ShadowTLSHandler)(nil)
	_ caddy.Provisioner     = (*ShadowTLSHandler)(nil)
	_ caddyfile.Unmarshaler = (*ShadowTLSHandler)(nil)
	_ layer4.NextHandler    = (*ShadowTLSHandler)(nil)
)

// Used to properly shutdown half-closed connections (see PR #73).
// Implemented by net.TCPConn, net.UnixConn, tls.Conn, qtls.Conn.
type closeWriter interface {
	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

// Ensure we notice if CloseWrite changes for these important connections
var (
	_ closeWriter = (*net.TCPConn)(nil)
	_ closeWriter = (*net.UnixConn)(nil)
	_ closeWriter = (*tls.Conn)(nil)
)
