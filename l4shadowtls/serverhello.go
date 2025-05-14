package l4shadowtls

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

type CurveID uint16

type keyShare struct {
	group CurveID
	data  []byte
}

type serverHelloMsg struct {
	original                     []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	ocspStapling                 bool
	ticketSupported              bool
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool
	alpnProtocol                 string
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16
	supportedPoints              []uint8
	encryptedClientHello         []byte
	serverNameAck                bool

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup CurveID
}

func parseRawServerHello(data []byte) (*serverHelloMsg, error) {
	m := &serverHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return nil, fmt.Errorf("failed to parse server hello")
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return m, nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, fmt.Errorf("failed to parse server hello extensions")
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
		}

		if seenExts[extension] {
			return nil, fmt.Errorf("duplicate server hello extension: %d", extension)
		}
		seenExts[extension] = true

		switch extension {
		case extensionStatusRequest:
			m.ocspStapling = true
		case extensionSessionTicket:
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
			m.secureRenegotiationSupported = true
		case extensionExtendedMasterSecret:
			m.extendedMasterSecret = true
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
			m.alpnProtocol = string(proto)
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
				}
				m.scts = append(m.scts, sct)
			}
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.supportedVersion) {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.selectedGroup)) {
					return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.serverShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.serverShare.data) {
					return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
				}
			}
		case extensionPreSharedKey:
			m.selectedIdentityPresent = true
			if !extData.ReadUint16(&m.selectedIdentity) {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
		case extensionEncryptedClientHello: // encrypted_client_hello
			m.encryptedClientHello = make([]byte, len(extData))
			if !extData.CopyBytes(m.encryptedClientHello) {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
		case extensionServerName:
			if len(extData) != 0 {
				return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
			}
			m.serverNameAck = true
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return nil, fmt.Errorf("failed to parse server hello extensions: %d", extension)
		}
	}

	return m, nil
}
