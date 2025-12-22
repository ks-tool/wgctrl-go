package wgtypes

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

// A DeviceType specifies the underlying implementation of a WireGuard device.
type DeviceType int

// Possible DeviceType values.
const (
	Unknown DeviceType = iota
	LinuxKernel
	OpenBSDKernel
	FreeBSDKernel
	WindowsKernel
	Userspace
)

// String returns the string representation of a DeviceType.
func (dt DeviceType) String() string {
	switch dt {
	case LinuxKernel:
		return "Linux kernel"
	case OpenBSDKernel:
		return "OpenBSD kernel"
	case FreeBSDKernel:
		return "FreeBSD kernel"
	case WindowsKernel:
		return "Windows kernel"
	case Userspace:
		return "userspace"
	default:
		return "unknown"
	}
}

// A Device is a WireGuard device.
type Device struct {
	// Name is the name of the device.
	Name string

	// Type specifies the underlying implementation of the device.
	Type DeviceType

	// PrivateKey is the device's private key.
	PrivateKey Key

	// PublicKey is the device's public key, computed from its PrivateKey.
	PublicKey Key

	// ListenPort is the device's network listening port.
	ListenPort int

	// FirewallMark is the device's current firewall mark.
	//
	// The firewall mark can be used in conjunction with firewall software to
	// take action on outgoing WireGuard packets.
	FirewallMark int

	IsAmnezia bool

	// Peers is the list of network peers associated with this device.
	Peers []Peer
}

// KeyLen is the expected key length for a WireGuard key.
const KeyLen = 32 // wgh.KeyLen

// A Key is a public, private, or pre-shared secret key.  The Key constructor
// functions in this package can be used to create Keys suitable for each of
// these applications.
type Key [KeyLen]byte

// GenerateKey generates a Key suitable for use as a pre-shared secret key from
// a cryptographically safe source.
//
// The output Key should not be used as a private key; use GeneratePrivateKey
// instead.
func GenerateKey() (Key, error) {
	b := make([]byte, KeyLen)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("wgtypes: failed to read random bytes: %v", err)
	}

	return NewKey(b)
}

// GeneratePrivateKey generates a Key suitable for use as a private key from a
// cryptographically safe source.
func GeneratePrivateKey() (Key, error) {
	key, err := GenerateKey()
	if err != nil {
		return Key{}, err
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// NewKey creates a Key from an existing byte slice.  The byte slice must be
// exactly 32 bytes in length.
func NewKey(b []byte) (Key, error) {
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("wgtypes: incorrect key size: %d", len(b))
	}

	var k Key
	copy(k[:], b)

	return k, nil
}

// ParseKey parses a Key from a base64-encoded string, as produced by the
// Key.String method.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("wgtypes: failed to parse base64-encoded key: %v", err)
	}

	return NewKey(b)
}

// PublicKey computes a public key from the private key k.
//
// PublicKey should only be called when k is a private key.
func (k Key) PublicKey() Key {
	var (
		pub  [KeyLen]byte
		priv = [KeyLen]byte(k)
	)

	// ScalarBaseMult uses the correct base value per https://cr.yp.to/ecdh.html,
	// so no need to specify it.
	curve25519.ScalarBaseMult(&pub, &priv)

	return Key(pub)
}

// String returns the base64-encoded string representation of a Key.
//
// ParseKey can be used to produce a new Key from this string.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// A Peer is a WireGuard peer to a Device.
type Peer struct {
	// PublicKey is the public key of a peer, computed from its private key.
	//
	// PublicKey is always present in a Peer.
	PublicKey Key

	// PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
	//
	// A zero-value Key means no preshared key is configured.
	PresharedKey Key

	// Endpoint is the most recent source address used for communication by
	// this Peer.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies how often an "empty" packet is sent
	// to a peer to keep a connection alive.
	//
	// A value of 0 indicates that persistent keepalives are disabled.
	PersistentKeepaliveInterval time.Duration

	// LastHandshakeTime indicates the most recent time a handshake was performed
	// with this peer.
	//
	// A zero-value time.Time indicates that no handshake has taken place with
	// this peer.
	LastHandshakeTime time.Time

	// ReceiveBytes indicates the number of bytes received from this peer.
	ReceiveBytes int64

	// TransmitBytes indicates the number of bytes transmitted to this peer.
	TransmitBytes int64

	// AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
	AllowedIPs []net.IPNet

	// ProtocolVersion specifies which version of the WireGuard protocol is used
	// for this Peer.
	//
	// A value of 0 indicates that the most recent protocol version will be used.
	ProtocolVersion int
}

// A Config is a WireGuard device configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a device.
type Config struct {
	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the private key.
	PrivateKey *Key

	// ListenPort specifies a device's listening port, if not nil.
	ListenPort *int

	// FirewallMark specifies a device's firewall mark, if not nil.
	//
	// If non-nil and set to 0, the firewall mark will be cleared.
	FirewallMark *int

	// ReplacePeers specifies if the Peers in this configuration should replace
	// the existing peer list, instead of appending them to the existing list.
	ReplacePeers bool

	// Peers specifies a list of peer configurations to apply to a device.
	Peers []PeerConfig

	// --- AmneziaWG Specific Configuration ---
	// All fields are pointers to handle "optional update" semantics.

	// Junk Packet parameters
	Jc   *int // Count
	Jmin *int // Min size
	Jmax *int // Max size

	// Message Padding parameters (bytes)
	S1 *int // Init
	S2 *int // Response
	S3 *int // Cookie
	S4 *int // Transport

	// Message Magic Headers
	// In AmneziaWG these can be ranges ("123-456") or single values. Hence string.
	H1 *string // Init
	H2 *string // Response
	H3 *string // Cookie
	H4 *string // Transport

	// Init Packet Magic / Custom Signature (obfuscation)
	I1 *string
	I2 *string
	I3 *string
	I4 *string
	I5 *string
}

// generateAmneziaParams populates the config with obfuscation values.
func (cfg *Config) GenerateAmneziaParams() {
	// 1. Initialize random source.
	// We use standard math/rand because this is for obfuscation (fooling DPI),
	// not for cryptography (encryption is handled by WireGuard keys).
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// ==========================================
	// 1. JUNK PACKETS (Jc, Jmin, Jmax)
	// These packets are sent BEFORE the handshake to look like random noise.
	// ==========================================

	// Jc: Packet Count.
	// We send between 3 and 7 junk packets.
	// High values (e.g., >20) delay the connection start. 3-7 is optimal.
	cfg.Jc = intPtr(3 + r.Intn(5))

	// Jmin/Jmax: Packet Size (Bytes).
	// We keep them small (~40-90 bytes) to resemble TCP ACK/SYN packets.
	// We ensure Jmax is significantly smaller than MTU (usually 1280 or 1500).
	cfg.Jmin = intPtr(40 + r.Intn(20))             // 40-59 bytes
	cfg.Jmax = intPtr(*cfg.Jmin + 20 + r.Intn(40)) // Jmin + (20-59 bytes)

	// ==========================================
	// 2. PACKET PADDING (S1, S2...)
	// These values add random garbage bytes to the END of WireGuard packets.
	// This breaks the fixed size signatures of the protocol.
	// ==========================================

	// S1: Init Message Padding (Bytes).
	// Standard WG Init packet is exactly 148 bytes.
	// We add 20-100 bytes. The packet remains small enough to travel safely.
	cfg.S1 = intPtr(20 + r.Intn(80))

	// S2: Response Message Padding (Bytes).
	// Standard WG Response is 92 bytes.
	cfg.S2 = intPtr(20 + r.Intn(80))

	// S3: Cookie Message Padding.
	// Rarely sent, but good to mask just in case.
	cfg.S3 = intPtr(10 + r.Intn(30))

	// S4: Transport Data Padding.
	// IMPORTANT: This adds bytes to EVERY data packet (YouTube, downloads, etc).
	// We keep it at 0 to avoid bandwidth overhead and speed loss.
	cfg.S4 = intPtr(0)

	// ==========================================
	// 3. MAGIC HEADERS (H1 - H4)
	// These emulate the Packet ID (uint32).
	// Standard WireGuard uses 1, 2, 3, 4. Amnezia allows custom values.
	// ==========================================

	// We generate distinct, static random integers for each header type.
	// We use a safe offset (e.g. > 1,000,000) to avoid conflict with standard protocols.
	// The maximum value for uint32 is ~4 Billion.

	// Helper to generate a static string representation of a random uint32
	genStaticHeader := func() *string {
		// Generate a random number between 100,000,000 and 2,100,000,000
		val := 100000000 + r.Intn(2000000000)
		res := fmt.Sprintf("%d", val)
		return &res
	}

	cfg.H1 = genStaticHeader() // Handshake Initiation
	cfg.H2 = genStaticHeader() // Handshake Response
	cfg.H3 = genStaticHeader() // Cookie Reply
	cfg.H4 = genStaticHeader() // Transport Data

	// Init-packets (I1..I5) are usually for specific protocol emulation (TLS/DTLS).
	// General recommendation is to use it on the client side only
}

// intPtr is a helper to get a pointer to an int generic literal
func intPtr(i int) *int {
	return &i
}

// TODO(mdlayher): consider adding ProtocolVersion in PeerConfig.

// A PeerConfig is a WireGuard device peer configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// PeerConfig fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a peer.
type PeerConfig struct {
	// PublicKey specifies the public key of this peer.  PublicKey is a
	// mandatory field for all PeerConfigs.
	PublicKey Key

	// Remove specifies if the peer with this public key should be removed
	// from a device's peer list.
	Remove bool

	// UpdateOnly specifies that an operation will only occur on this peer
	// if the peer already exists as part of the interface.
	UpdateOnly bool

	// PresharedKey specifies a peer's preshared key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the preshared key.
	PresharedKey *Key

	// Endpoint specifies the endpoint of this peer entry, if not nil.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies the persistent keepalive interval
	// for this peer, if not nil.
	//
	// A non-nil value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval *time.Duration

	// ReplaceAllowedIPs specifies if the allowed IPs specified in this peer
	// configuration should replace any existing ones, instead of appending them
	// to the allowed IPs list.
	ReplaceAllowedIPs bool

	// AllowedIPs specifies a list of allowed IP addresses in CIDR notation
	// for this peer.
	AllowedIPs []net.IPNet
}
