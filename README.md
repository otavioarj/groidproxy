# Groid v1.0.2 – Golang Android Proxier

## 📦 Usage

```bash
./groidproxy [options] [packages...]
```

## ⚙️ Options

| Flag               | Description                                                                                      					 |
|--------------------|-------------------------------------------------------------------------------------------------------------|
| `-blacklist string`| Comma-separated list of blocked hosts/IPs (`.domain.com` for wildcards)<br>❗Not supported in raw mode |
| `-d`               | Run as daemon                                                                                   						 |
| `-dns`             | Also redirect DNS (port 53)                                                                      					 |
| `-flush`           | Remove all GROID rules                                                                           					 |
| `-global`          | Redirect all traffic                                                                             					 |
| `-list`            | List current rules                                                                               					 |
| `-local-port int`  | Local port for transparent proxy (default: `8123`)                                               					 |
| `-p string`        | Proxy address (`host:port`, `http://host:port`, or `socks5://host:port`)                         					 |
| `-remove string`   | Remove rules for specified package                                                               					 |
| `-stats`           | Show I/O statistics                                                                              					 |
| `-timeout int`     | Connection timeout in seconds (default: `10`)                                                    					 |
| `-v`               | Verbose output                                                                                   					 |

## 🧰 Proxy Modes

- `host:port` — Redirect TCP packets to an external transparent proxy  
- `http://host:port` — Transparent redirect to an HTTP proxy  
- `socks5://host:port` — Transparent redirect to a SOCKS5 proxy

## 🔍 Examples

```bash
./groidproxy -p 192.168.1.100:8888 com.example.app
./groidproxy -p http://192.168.1.100:8080 com.example.app com.android.chrome
./groidproxy -p socks5://192.168.1.100:1080 -global
./groidproxy -p socks5://192.168.1.100:1080 -blacklist "facebook.com,.youtube.com" com.example.app
```
