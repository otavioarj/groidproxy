# GoDroid v1.0.0 – Golang Android Proxier

## 📦 Usage

```bash
./groidproxy [options] [packages...]
```

## ⚙️ Options

| Flag             | Description                                                       |
|------------------|-------------------------------------------------------------------|
| `-d`             | Run as daemon                                                     |
| `-dns`           | Also redirect DNS (port 53)                                       |
| `-flush`         | Remove all GROID rules                                            |
| `-global`        | Redirect all traffic                                              |
| `-list`          | List current rules                                                |
| `-local-port`    | Local port for transparent proxy (default: `8123`)                |
| `-p string`      | Proxy address (`host:port`, `http://host:port`, or `socks5://host:port`)|
| `-remove string` | Remove rules for specified package                                |
| `-stats`         | Show I/O statistics                                               |
| `-timeout int`   | Connection timeout in seconds (default: `10`)                     |
| `-v`             | Verbose output                                                    |

## 🧰 Proxy Modes (-p)

- `host:port` — Redirect to a transparent proxy  
- `http://host:port` — Transparent redirect to an HTTP proxy  
- `socks5://host:port` — Transparent redirect to a SOCKS5 proxy

## 🔍 Examples

```bash
./groidproxy -p 192.168.1.100:8888 com.example.app
./groidproxy -p http://192.168.1.100:8080 com.example.app com.android.chrome
./groidproxy -p socks5://192.168.1.100:1080 -global
```
