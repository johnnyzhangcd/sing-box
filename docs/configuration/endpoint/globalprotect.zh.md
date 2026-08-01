---
icon: material/new-box
---

!!! note

    GlobalProtect 支持需要使用 `-tags with_globalprotect,with_gvisor` 构建的 sing-box。
    该实现是纯 Go 的，运行时不需要 `openconnect` 或 `libopenconnect`。
    sing-box 会使用用户态隧道并接入 sing-tun 的 gVisor stack，因此 TCP 和 UDP 都能工作，而且不需要 kernel TUN 权限。
    启动过程不会阻塞：端点会在后台连接并重试，其他 sing-box 服务可以先进入就绪状态。
    门户、网关和 HIP 请求默认使用各自真实目标的 TLS 身份，只有显式设置 `sni` 时才固定覆盖。
    当网关要求 HIP 时，sing-box 会在登录时提交报告，并按门户下发的周期重新检查。

    内置 HIP 报告提供尽力而为的标准主机信息。如果部署要求厂商专用 HIP wrapper、定制脚本或额外合规字段，
    网关仍可能拒绝或隔离该会话。

### 结构

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
  "reconnect_timeout": "5m",

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

GlobalProtect 门户或网关的主机名。也可以直接提供完整的 `https://` URL。

#### server_port

当 `server` 未包含端口时使用的 TCP 端口。

如果 `server` 已经是完整 URL 或已经包含端口，则忽略此项。

#### username

==必填==

用于门户认证的账号名。

#### password

门户要求密码时使用的密码。

#### auth_group

当存在多个组时，用于选择 GlobalProtect 认证组。

#### server_cert

仅接受匹配的服务器证书指纹。

格式与 OpenConnect 的 `--servercert` 相同，支持 `sha1:`、`sha256:` 和 `pin-sha256:` 前缀。

#### ca_file

额外用于服务器验证的 CA 文件。

#### no_system_trust

不信任系统证书颁发机构。

#### sni

覆盖 TLS 握手中发送的 SNI 主机名。

#### local_hostname

覆盖向门户报告的主机名。

默认使用系统主机名。

#### reported_os

覆盖向门户报告的操作系统字符串。

支持的值包括 `linux`、`linux-64`、`win`、`mac-intel`、`android` 和 `apple-ios`。

#### disable_ipv6

不向服务器通告 IPv6 能力。

#### disable_dtls

兼容从 OpenConnect 迁移过来的配置。

纯 Go GlobalProtect 端点始终使用 TLS/GPST；目前未实现 DTLS 和 ESP。

#### proxy

用于 GlobalProtect 控制连接和隧道连接的 SOCKS 代理 URL。

#### allow_insecure_crypto

允许旧式加密，包括 SHA1、3DES 和 RC4。

#### pfs

要求 TLS 通道使用 Perfect Forward Secrecy。

#### reconnect_timeout

每次首次连接或重连尝试的最长时间。
只要端点仍在运行，失败后就会继续重试。

默认使用 `5m`。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/) 了解详情。
