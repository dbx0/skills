# [Seed] IoT Router Firmware Extraction + Root via UART Serial

## Scenario Category
Firmware / IoT security

## Target Overview
A low- to mid-range home router. Pull the firmware bin from the vendor site, extract the squashfs with binwalk, then attach a serial adapter to the device's UART to get a root shell and analyze the web management interface and startup scripts.

## Full Execution Chain

### Part 1: Firmware analysis

1. Download the firmware file (vendor site / OpenWRT / dump the flash yourself)
2. Basic identification
   ```bash
   file firmware.bin
   binwalk firmware.bin                    # look for LZMA / SquashFS / U-Boot
   binwalk -E firmware.bin                 # entropy graph tells you whether it is encrypted
   ```
3. Extract
   ```bash
   binwalk -e firmware.bin
   cd _firmware.bin.extracted/squashfs-root
   ```
4. Key static analysis points
   ```bash
   find . -name 'shadow' -exec cat {} \;          # default password hashes
   find . -name '*.cgi' -o -name 'lighttpd*'      # web services
   find . -name 'rcS' -o -name 'init.d'           # startup scripts
   grep -r 'telnetd\|busybox' .                   # suspicious backdoors
   strings $(find . -name 'httpd') | grep -i 'admin\|debug\|backdoor'
   ```
5. Take `/etc/shadow` and crack it offline:
   ```bash
   john --wordlist=rockyou.txt shadow
   ```

### Part 2: Hardware UART

1. Open the case and inspect the PCB, looking for an unpopulated 4-pin / 6-pin header (usually unsoldered, sometimes with pins already fitted)
2. Identify the pins with a multimeter
   - GND (continuity to the ground plane)
   - VCC (3.3V, steady during boot)
   - TX (lots of level transitions during boot, output flowing UART -> PC)
   - RX (essentially unchanging during boot)
3. Wire up a USB-TTL adapter (CP2102 / FT232)
   - Router TX -> USB-TTL RX
   - Router RX -> USB-TTL TX
   - Router GND -> USB-TTL GND
   - **Do not connect VCC** (the device is self-powered)
4. Open a serial listener on the host
   ```bash
   sudo screen /dev/ttyUSB0 115200
   # or: minicom / picocom
   ```
5. Power on, watch the U-Boot output, then the Linux boot, which usually lands on a login prompt
6. Try default credentials or the cracked shadow password to get a root shell

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| binwalk extraction produced an empty directory | Some firmware uses a non-standard format (vendor-proprietary header) | Slice it out manually with `dd` against the offsets, or use `unblob` instead of binwalk | 1h |
| binwalk -E shows entropy close to 1 | The whole image is encrypted | Find the decryption key used during firmware upgrade (usually hardcoded in the OEM tool)| several hours |
| No characters at all on the UART | Wrong baud rate | Try 9600 / 38400 / 57600 / 115200 / 460800 / 921600 | 30min |
| Characters appear on the UART but are garbage | TX/RX swapped, or voltage level mismatch | 1) Swap TX and RX  2) Confirm the USB-TTL is 3.3V and not 5V | 30min |
| Login prompt but no usable password | Nothing cracked, and the vendor default was changed | Interrupt at the U-Boot stage with a keypress -> `setenv bootargs ${bootargs} init=/bin/sh` -> drop into single user | 1.5h |
| U-Boot does not respond to the interrupt keypress | The vendor disabled the console or changed the prompt | Look for `bootdelay` in the firmware, or physically short the SPI flash to force a boot failure so U-Boot drops to its interactive prompt | several hours |
| Got root but telnetd does not work | The image ships neither dropbear nor telnetd | Mount USB storage and copy a busybox-static binary onto the device | 1h |

## Toolchain Findings

- **unblob** is stronger than binwalk (recognizes more formats automatically and does not choke on proprietary headers)
- **firmware-mod-kit** is old but still works for unpacking/repacking
- **firmwalker** automatically scans an extracted squashfs for "sensitive leads" (credentials/private keys/URLs/backdoored binaries)
- **EMBA** is a full firmware audit platform (automated firmwalker + binary CVE scanning + emulated boot)
- **FirmAE** boots IoT firmware under QEMU so you can analyze the web interface dynamically without the real hardware
- **ChirpStack USB-TTL** / **Bus Pirate** / **Tigard** all work, and a cheap CP2102 is good enough

## Key Code/Commands

End-to-end firmware audit:

```bash
# 1. Extract
unblob -k firmware.bin -o extracted/

# 2. Run firmwalker
git clone https://github.com/craigz28/firmwalker
./firmwalker.sh extracted/squashfs-root

# 3. Emulated boot (if supported)
docker run -it --rm -v $(pwd):/firmware firmae:latest \
  /work/run.sh -d 1 /firmware/firmware.bin

# 4. Once the web interface is up under emulation, scan it directly with nuclei / nikto / curl
```

Automatically trying common UART baud rates:

```bash
for baud in 9600 19200 38400 57600 115200 460800 921600; do
    echo "--- $baud ---"
    timeout 3 sudo cat /dev/ttyUSB0 < <(stty -F /dev/ttyUSB0 $baud cs8 -cstopb -parenb)
done
```

Classic U-Boot single-user bypass:

```text
# Interrupt at the U-Boot stage with a keypress (usually holding space or Ctrl+C)
=> setenv bootargs "console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/bin/sh"
=> saveenv
=> boot
# boots straight into sh, no password needed
```

## Suggested Improvements to This Package

- `reverse-engineering/platforms.md` already has a firmware chapter; split out a `references/iot-firmware-cheatsheet.md`
- Add `reverse-engineering/references/uart-debug.md` covering UART/JTAG/SWD basics
- Add unblob / firmwalker to the bootstrap manifest

## Reusable Patterns/Script Snippets

**Four phases of IoT security testing**:

```text
Phase 1 - Software
  - Download vendor firmware + extract with binwalk/unblob
  - Run firmwalker over it
  - grep for default credentials / private keys / backdoor strings
  - Boot under QEMU emulation and run web vulnerability scans

Phase 2 - Hardware
  - Open the case and find the UART/JTAG pads
  - Identify GND/VCC/TX/RX with a multimeter
  - Wire the USB-TTL adapter, confirming 3.3V levels

Phase 3 - Debugging
  - Listen with screen/minicom
  - Interrupt at the U-Boot stage to get the interactive prompt
  - init=/bin/sh for a single-user password bypass

Phase 4 - Exploitation
  - With root, pull /etc/shadow and crack it offline
  - Review the web management CGI binaries for command injection / SSRF
  - Review the UPnP / mDNS / Bluetooth advertising logic
```

**Default credential quick reference** (common vendor defaults):

```text
admin / admin
admin / password
root / root
root / 1234
support / support
ubnt / ubnt          # Ubiquiti
admin / 1234         # ZyXEL
```

## Evolution Actions
- [ ] Split out iot-firmware-cheatsheet.md
- [ ] Create uart-debug.md
- [ ] Add unblob / firmwalker to bootstrap-manifest

## Environment Details
- Kali 2026.x (binwalk / unblob / squashfs-tools / firmwalker)
- USB-TTL adapter: CP2102 / FT232 (3.3V levels)
- Target: ARMv7 / MIPS routers (OpenWRT-derived firmware is common)

## Redaction Requirements
This entry is seed data written from publicly documented IoT security testing methods and does not involve any real vendor or model.
