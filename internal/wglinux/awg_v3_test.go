//go:build linux
// +build linux

package wglinux

import (
	"strings"
	"testing"
	"time"

	"github.com/Jipok/wgctrl-go/internal/wgtest"
	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// amneziawg-dkms v3.0 (genl family version 3) wire-format changes:
// WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL is a u32 (u16 in mainline WireGuard
// and amneziawg-dkms v1.x), WGDEVICE_A_H1..H4 are u64 values (strings before).
// These tests cover both directions: parsing device dumps from either module
// generation, and encoding config attributes at the right width for the
// family version the kernel reported.

// peerWithKeepalive builds a single-peer device message whose keepalive
// attribute carries the given raw payload.
func peerWithKeepalive(t *testing.T, keepalive []byte) genetlink.Message {
	t.Helper()
	key := wgtest.MustPublicKey()

	return genetlink.Message{
		Data: m([]netlink.Attribute{
			{
				Type: unix.WGDEVICE_A_IFNAME,
				Data: nlenc.Bytes("wg0"),
			},
			{
				Type: unix.WGDEVICE_A_PEERS,
				Data: m(netlink.Attribute{
					Type: 0,
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGPEER_A_PUBLIC_KEY,
							Data: key[:],
						},
						{
							Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
							Data: keepalive,
						},
					}...),
				}),
			},
		}...),
	}
}

func Test_parseDeviceKeepaliveWidths(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    time.Duration
	}{
		{
			name:    "u16 mainline and dkms v1.x",
			payload: nlenc.Uint16Bytes(10),
			want:    10 * time.Second,
		},
		{
			name:    "u32 dkms v3.0",
			payload: nlenc.Uint32Bytes(25),
			want:    25 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := parseDevice([]genetlink.Message{peerWithKeepalive(t, tt.payload)})
			if err != nil {
				t.Fatalf("parseDevice: %v", err)
			}
			if len(d.Peers) != 1 {
				t.Fatalf("got %d peers, want 1", len(d.Peers))
			}
			if got := d.Peers[0].PersistentKeepaliveInterval; got != tt.want {
				t.Fatalf("keepalive = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseDeviceKeepaliveBadLength(t *testing.T) {
	_, err := parseDevice([]genetlink.Message{peerWithKeepalive(t, []byte{1, 2, 3})})
	if err == nil {
		t.Fatal("parseDevice accepted a 3-byte keepalive attribute")
	}
	if !strings.Contains(err.Error(), "keepalive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// firstPeerAttrs decodes configAttrs output down to the first peer's raw
// attributes, keyed by attribute type.
func firstPeerAttrs(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	attrs := deviceAttrs(t, b)
	peers, ok := attrs[unix.WGDEVICE_A_PEERS]
	if !ok {
		t.Fatal("no WGDEVICE_A_PEERS attribute encoded")
	}

	arr, err := netlink.UnmarshalAttributes(peers)
	if err != nil {
		t.Fatalf("unmarshal peers array: %v", err)
	}
	if len(arr) == 0 {
		t.Fatal("empty peers array")
	}

	peer, err := netlink.UnmarshalAttributes(arr[0].Data)
	if err != nil {
		t.Fatalf("unmarshal first peer: %v", err)
	}
	out := make(map[uint16][]byte, len(peer))
	for _, a := range peer {
		out[a.Type&0x3fff] = a.Data
	}
	return out
}

// deviceAttrs decodes configAttrs output into device-level raw attributes,
// keyed by attribute type with the NLA_F_NESTED/NLA_F_NET_BYTEORDER flag bits
// masked off (UnmarshalAttributes keeps them in Type).
func deviceAttrs(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		t.Fatalf("unmarshal device attributes: %v", err)
	}
	out := make(map[uint16][]byte, len(attrs))
	for _, a := range attrs {
		out[a.Type&0x3fff] = a.Data
	}
	return out
}

func Test_configAttrsKeepaliveWidthByFamilyVersion(t *testing.T) {
	dur := 10 * time.Second
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   wgtest.MustPublicKey(),
			PersistentKeepaliveInterval: &dur,
		}},
	}

	tests := []struct {
		name    string
		version uint8
		wantLen int
	}{
		{name: "mainline v1", version: 1, wantLen: 2},
		{name: "amnezia dkms v1.x (genl 2)", version: 2, wantLen: 2},
		{name: "amnezia dkms v3.0 (genl 3)", version: genlVersionAWG3, wantLen: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := configAttrs("wg0", cfg, tt.version)
			if err != nil {
				t.Fatalf("configAttrs: %v", err)
			}
			ka, ok := firstPeerAttrs(t, b)[unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]
			if !ok {
				t.Fatal("no keepalive attribute encoded")
			}
			if len(ka) != tt.wantLen {
				t.Fatalf("keepalive attribute length = %d, want %d", len(ka), tt.wantLen)
			}
		})
	}
}

func Test_configAttrsMagicHeadersByFamilyVersion(t *testing.T) {
	h1 := "123456"
	cfg := wgtypes.Config{H1: &h1}

	// genl 2 (dkms v1.x): NUL-terminated string, ranges allowed.
	b, err := configAttrs("wg0", cfg, 2)
	if err != nil {
		t.Fatalf("configAttrs(v2): %v", err)
	}
	got, ok := deviceAttrs(t, b)[WGDEVICE_A_H1]
	if !ok {
		t.Fatal("v2: no H1 attribute encoded")
	}
	if s := nlenc.String(got); s != h1 {
		t.Fatalf("v2: H1 = %q, want %q", s, h1)
	}

	// genl 3 (dkms v3.0): single u64 value.
	b, err = configAttrs("wg0", cfg, genlVersionAWG3)
	if err != nil {
		t.Fatalf("configAttrs(v3): %v", err)
	}
	got, ok = deviceAttrs(t, b)[WGDEVICE_A_H1]
	if !ok {
		t.Fatal("v3: no H1 attribute encoded")
	}
	if len(got) != 8 {
		t.Fatalf("v3: H1 attribute length = %d, want 8", len(got))
	}
	if v := nlenc.Uint64(got); v != 123456 {
		t.Fatalf("v3: H1 = %d, want 123456", v)
	}
}

func Test_configAttrsMagicHeaderRangeRejectedOnV3(t *testing.T) {
	h1 := "123456-123999"
	cfg := wgtypes.Config{H1: &h1}

	if _, err := configAttrs("wg0", cfg, genlVersionAWG3); err == nil {
		t.Fatal("configAttrs(v3) accepted a range magic header")
	}

	// The same range must still encode fine for dkms v1.x.
	if _, err := configAttrs("wg0", cfg, 2); err != nil {
		t.Fatalf("configAttrs(v2) rejected a range magic header: %v", err)
	}
}
