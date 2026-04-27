# `pagejaune`

**pagejaune** is a recursive DNS resolver implemented as a unikernel. It
resolves DNS queries by talking directly to root servers, without relying on
any third-party resolver (such as `8.8.8.8` or `1.1.1.1`). The project is
written in OCaml 5 and runs as a [Solo5][solo5] unikernel using the `hvt`
backend.

## Features

- Recursive DNS resolution starting from root servers
- UDP, TCP and TLS (DNS-over-TLS) support
- TCP/TLS connection reuse to authoritative servers
- Built-in DNS cache
- Opportunistic TLS to authoritative servers
- DNSSEC (experimental)
- QNAME minimisation ([RFC 9156](https://datatracker.ietf.org/doc/html/rfc9156))

## Prerequisites

- OCaml >= 5.3.0
- [opam](https://opam.ocaml.org/)
- [Solo5](https://github.com/Solo5/solo5) (for `solo5-hvt`)
- GNU Make

## Building

```bash
git clone https://github.com/dinosaure/pagejaune
cd pagejaune
opam pin add -yn .
./source.sh
make all
```

This produces the `pagejaune.hvt` binary, a standalone ELF executable for the
Solo5/hvt backend.

## Network setup

The `net.sh` script sets up a bridge and a tap device to connect the unikernel
to the host network. It also allows the unikernel to communicate with the
Internet via the `wlan0` interface (to be configured according to your network).
```bash
./net.sh
```

This script creates:
- A `service` bridge with the address `10.0.0.1/24`
- A `tap0` tap device attached to the bridge
- iptables rules for NAT and forwarding

> **Note**: the script uses `wlan0` as the outbound interface. Adjust it to
> match your setup (e.g. `eth0`, `enp0s3`).

## Usage

```bash
solo5-hvt --net:service=tap0 -- pagejaune.hvt \
  --ipv4=10.0.0.2/24 \
  --ipv4-gateway=10.0.0.1
```

You can test with `dig`:
```bash
dig robur.coop @10.0.0.2
```

### Options

| Option                              | Description                                   |
|-------------------------------------|-----------------------------------------------|
| `--ipv4=CIDR`                       | IPv4 address and netmask (e.g. `10.0.0.2/24`) |
| `--ipv4-gateway=ADDR`               | IPv4 gateway                                  |
| `--ipv6`                            | Enable IPv6 support                           |
| `--dnssec`                          | Enable DNSSEC validation                      |
| `--opportunistic-tls-authoritative` | Opportunistic TLS to authoritative servers    |
| `--qname-minimisation`              | Enable QNAME minimisation                     |
| `-a`, `--authenticator`             | X.509 authenticator for TLS validation        |
| `-l REGEXP`                         | Filter logs by regular expression             |
| `-v`, `-vv`, `-vvv`                 | Verbosity level                               |

## License

MIT - [Robur](https://robur.coop/)

[solo5]: https://github.com/solo5/solo5
