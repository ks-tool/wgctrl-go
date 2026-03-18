package wgtypes

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
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
	if _, err := crand.Read(b); err != nil {
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
	// In AmneziaWG 2.0 these should be ranges (e.g., "123456-123999")
	H1 *string // Init
	H2 *string // Response
	H3 *string // Cookie
	H4 *string // Transport

	// Init Packet Magic / Custom Signature (obfuscation)
	// For client-side explicit setups only.
	I1 *string
	I2 *string
	I3 *string
	I4 *string
	I5 *string
}

// GenerateAmneziaParams populates the config with obfuscation values optimized for AWG 2.0.
func (cfg *Config) GenerateAmneziaParams() {
	// ==========================================
	// 1. PRE-SESSION JUNK PACKETS (Jc, Jmin, Jmax)
	// Doc limits: Jc 0-10, Jmin/Jmax 64-1024 bytes.
	// We avoid packets smaller than 64 bytes so DPI doesn't flag them as anomalies.
	// ==========================================

	cfg.Jc = intPtr(3 + rand.IntN(4)) // 3 to 6 packets

	// AWG Go core easily handles up to 1024. We wanna look like UDP app traffic.
	cfg.Jmin = intPtr(64 + rand.IntN(50))              // 64-113 bytes
	cfg.Jmax = intPtr(*cfg.Jmin + 50 + rand.IntN(100)) // Jmin + (50-149 bytes)

	// ==========================================
	// 2. PACKET PADDING (S1, S2, S3, S4)
	// Doc limits: S1-S3: 0-64 bytes. S4: 0-32 bytes.
	// Base standard WG sizes: Init=148, Resp=92, Cookie=64.
	// Random garbage bytes prepended to the START of WireGuard packets.
	// ==========================================

	for {
		// Strict limits to prevent high overhead while breaking WG signature
		s1 := 15 + rand.IntN(49) // 15-63 bytes
		s2 := 15 + rand.IntN(49) // 15-63 bytes
		s3 := 10 + rand.IntN(54) // 10-63 bytes
		s4 := 1 + rand.IntN(15)  // 1-15 bytes (keep Transport small to save MTU)

		// Rule A: All padding values must be unique
		if s1 == s2 || s1 == s3 || s1 == s4 || s2 == s3 || s2 == s4 || s3 == s4 {
			continue
		}

		// Rule B: Total resulting packet sizes must NEVER be equal
		// len(init) = 148 + s1, len(resp) = 92 + s2, len(cookie) = 64 + s3
		if s1+148 == s2+92 {
			continue
		} // Init and Resp collision
		if s3+64 == s1+148 {
			continue
		} // Cookie and Init collision
		if s3+64 == s2+92 {
			continue
		} // Cookie and Resp collision

		// Apply values and break the loop
		cfg.S1, cfg.S2, cfg.S3, cfg.S4 = intPtr(s1), intPtr(s2), intPtr(s3), intPtr(s4)
		break
	}

	// ==========================================
	// 3. MAGIC HEADERS RANGES (H1 - H4)
	// We generate 4 non-overlapping mathematical ranges (to satisfy the Go parser).
	// Then we shuffle them so that H1 < H2 < H3 < H4 is mathematically destroyed,
	// preventing heuristic DPI signature matching.
	// We keep max value below math.MaxInt32 to prevent integer
	// overflow crashes on legacy C++ clients which parse strings into signed ints.
	// ==========================================

	currentOffset := 150_000_000 + rand.IntN(50_000_000)
	ranges := make([]*string, 4)

	// Step 3.1: Generate strictly increasing non-overlapping ranges
	for i := 0; i < 4; i++ {
		rangeStart := currentOffset
		rangeEnd := rangeStart + 50_000_000 + rand.IntN(100_000_000)
		ranges[i] = strPtr(fmt.Sprintf("%d-%d", rangeStart, rangeEnd))

		// Add a guaranteed gap to prevent overlap
		currentOffset = rangeEnd + 10_000_000 + rand.IntN(20_000_000)
	}

	// Step 3.2: SHUFFLE THE RANGES (The Anti-Heuristic Magic)
	rand.Shuffle(len(ranges), func(i, j int) {
		ranges[i], ranges[j] = ranges[j], ranges[i]
	})

	// Step 3.3: Assign shuffled ranges to packet types
	cfg.H1 = ranges[0] // Handshake Initiation
	cfg.H2 = ranges[1] // Handshake Response
	cfg.H3 = ranges[2] // Cookie Reply
	cfg.H4 = ranges[3] // Transport Data

	// Init-packets (I1..I5) are usually for specific protocol emulation (TLS/DTLS).
	// From Doc:
	// If the parameter I1 is missing, the entire chain (I2-I5) is skipped, and AmneziaWG behaves as AmneziaWG 1.0, simplifying compatibility.
	i1Length := 15 + rand.IntN(26)
	cfg.I1 = strPtr(fmt.Sprintf("<r %d>", i1Length))
}

// intPtr is a helper to get a pointer to an int generic literal
func intPtr(i int) *int {
	return &i
}

func strPtr(s string) *string {
	return &s
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
