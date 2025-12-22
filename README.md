# wgctrl-go

This is a fork of [WireGuard/wgctrl-go](https://github.com/WireGuard/wgctrl-go) revised to support **AmneziaWG** (AWG). 

It provides native Go control over WireGuard/AmneziaWG devices on **Linux**, supporting both the **Kernel module** and **Userspace** implementations (via netlink and unix sockets).

## API Changes

### Device Structure
The `Device` struct now includes an `IsAmnezia` flag and identifies the implementation type.

```go
type Device struct {
    Name         string
    Type         DeviceType
    PublicKey    Key
    IsAmnezia    bool       // True if the device supports AmneziaWG obfuscation
    Peers        []Peer
    // ... other standard fields
}
```

### Amnezia Configuration
The `Config` struct is extended with Amnezia-specific fields (Jc, Jmin, Jmax, S1-S4, H1-H4). You can manually set these or use the helper:

```go
cfg := &wgtypes.Config{}
// Automatically populate Config with randomized obfuscation values to bypass DPI
cfg.GenerateAmneziaParams() 
```


## Projects using this library

*   **[jwg](https://github.com/Jipok/jwg)**: A lightweight CLI manager (~1k LOC) for WireGuard & AmneziaWG. Automates networking, nftables/UFW, and peer management.
*   **[dnsr](https://github.com/Jipok/dnsr)**: DNS-based selective routing tool for DPI bypass on Linux and routers.
