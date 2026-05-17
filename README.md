# DRD
### Discover | Report | Document

DRD is a lightweight network scanner written in C, focused on practical TCP/UDP port scanning, banner grabbing, and simple reporting.

It is being developed for low-level networking and cross-platform socket programming, with additional features being added over time.

<p align="center">
<img src="images/programlogo.png" width="300" height="300">
</p>

## Features

- TCP connect scanning
- Basic UDP probing (`open | filtered` detection)
- Banner grabbing for common services
- Simple banner-based version detection
- IPv4 support
- Limited IPv6 support
- CIDR range expansion (`192.168.1.0/24`)
- Top ports scanning (Top 20 / Top 100)
- HTML report generation
- Verbose output levels (`-v`, `-vv`, `-vvv`, `-q`)

---

## Planned / Experimental

- Improved IPv6 handling
- Rate limiting
- SOCKS5 proxy support
- SYN (stealth) scanning
- Stronger service/version detection
- Improved OS fingerprinting

---

## Installation
<p align="center">
  <img src="images/homedemo.png" width="500" height="500">
</p>
By default, there are two build scripts that come bundled with the program; one for Microsoft Windows and one for Linux builds. These are simple scripts that will compile the program, assuming you have GCC or another C++ compiler installed and configured. Alternatively, you can compile the program yourself using the commands provided below.

### Linux

```bash
gcc DRD_intel.c -o drd -pthread
```

### Windows
```commandprompt
gcc -O2 -Wall -o drd.exe drd_intel.c -lws2_32 -liphlpapi
```

----

## Example Usage
### Basic TCP scan

```bash
./drd example.com
```
### Scan a custom port range
```bash
./drd 192.168.1.1 -p 1-65535
```
