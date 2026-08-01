---
icon: material/new-box
---

!!! note

    GlobalProtect support requires sing-box to be built with `-tags with_globalprotect,with_gvisor`.
    The implementation is pure Go and does not require `openconnect` or `libopenconnect` at runtime.
    sing-box uses a user-space tunnel together with sing-tun's gVisor stack, so TCP and UDP both work without kernel TUN privileges.
    Startup is non-blocking by default: the endpoint connects and retries in the background while other sing-box services become ready.
    Enable `wait_for_ready` when a TUN inbound routes system traffic or DNS through this endpoint.
    Portal, gateway, and HIP requests use the TLS identity of their actual target unless `sni` explicitly overrides it.
    When required by the gateway, sing-box submits a HIP report during login and repeats the HIP check at the portal-defined interval.

    The built-in HIP report is a best-effort standard host inventory. Deployments that require a vendor-specific HIP wrapper,
    custom script, or additional compliance fields can still reject or quarantine the session.

### Structure

```json
{
  "type": "globalprotect",
  "tag": "gp-ep",

  "server": "vpn.example.com",
  "server_port": 1235,
  "username": "alice",
  "password": "secret",
  "auth_group": "",
  "server_cert": "",
  "ca_file": "",
  "no_system_trust": false,
  "sni": "",
  "local_hostname": "",
  "reported_os": "",
  "disable_ipv6": false,
  "disable_dtls": false,
  "proxy": "",
  "allow_insecure_crypto": false,
  "pfs": false,
  "wait_for_ready": false,
  "reconnect_timeout": "5m",

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The GlobalProtect portal or gateway host. You can also provide a full `https://` URL.

#### server_port

The TCP port used when `server` does not already include one.

Ignored when `server` is already a full URL or includes its own port.

#### username

==Required==

The account name used for portal authentication.

#### password

The password used when the portal asks for one.

#### auth_group

The GlobalProtect auth group to select when multiple groups are available.

#### server_cert

Accept only a matching server certificate fingerprint.

The format is the same as OpenConnect `--servercert`, including `sha1:`, `sha256:` and `pin-sha256:` prefixes.

#### ca_file

Additional CA file for server verification.

#### no_system_trust

Do not trust the system certificate authorities.

#### sni

Override the SNI hostname sent during TLS handshakes.

#### local_hostname

Override the hostname reported to the portal.

The system hostname is used by default.

#### reported_os

Optional compatibility override for the operating system string reported to the portal.

When omitted, the value is detected automatically from the runtime platform. macOS reports `mac-intel`
on both Intel and Apple Silicon, as required by the GlobalProtect protocol.

Supported values include `linux`, `linux-64`, `win`, `mac-intel`, `android`, and `apple-ios`.

#### disable_ipv6

Do not advertise IPv6 capability to the server.

#### disable_dtls

Compatibility field for configurations migrated from OpenConnect.

The pure-Go GlobalProtect endpoint always uses TLS/GPST; DTLS and ESP are not implemented.

#### proxy

SOCKS proxy URL used for GlobalProtect control and tunnel connections.

#### allow_insecure_crypto

Allow legacy crypto, including SHA1, 3DES, and RC4.

#### pfs

Require Perfect Forward Secrecy for the TLS channel.

#### wait_for_ready

Wait for the first GlobalProtect tunnel connection before starting sing-box inbounds.

When enabled, new outbound connections also wait for an in-progress tunnel reconnection and honor the caller's context timeout.
Enable this for a TUN inbound whose default route or DNS transport uses the GlobalProtect endpoint, so the TUN does not accept traffic before the tunnel is ready.

Disabled by default to preserve non-blocking startup for SOCKS and mixed inbounds.

#### reconnect_timeout

Maximum duration of each initial connection or reconnection attempt.
Failed attempts continue to retry while the endpoint is running.

`5m` will be used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
