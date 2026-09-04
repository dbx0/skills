# [Seed] Reversing a Custom Binary Protocol from a PCAP

## Scenario Category
Traffic capture analysis / protocol reversing

## Target Overview
An IoT device / desktop client speaks a custom binary protocol over TCP (not HTTP). A PCAP was captured, and the frame structure, field meanings, and encryption layer (if any) need to be recovered, then reproduced with a local client/server.

## Full Execution Chain

1. Open the PCAP in Wireshark and start with basic statistics
   - `Statistics → Conversations` to see IP/port pairs
   - `Statistics → I/O Graphs` to see the traffic rhythm
2. Identify the actual application-layer stream (strip out standard layers such as TLS)
3. On one TCP stream → `Follow → TCP Stream` → switch to RAW mode → export
4. Observe at the binary level: are the first few bytes of each frame a fixed magic / length field?
   ```bash
   xxd dump.bin | head -20
   ```
5. Look for patterns in hex mode: fixed header, length, TLV, CRC
6. Write a Python parser (struct + scapy) and decode frame by frame
7. In parallel, cross-check the protocol fields by decompiling the binary (look at the structs around send/recv in IDA / Ghidra)
8. Validation: stand up your own client, send a frame → the server responds the same way

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| Wireshark does not recognize the protocol, showing only "Data" | It is a proprietary protocol with no dissector | Write a Wireshark Lua dissector, or analyze it offline in Python | 30min |
| Looks patternless, every frame is different | There is a compression or encryption layer | Use entropy analysis (`ent dump.bin`) to judge whether it is encrypted, and look for nonce/IV fields | 1h |
| The length field does not add up | The length may be little-endian / big-endian, and may or may not include itself | Take several frames of different lengths and solve them as a system of equations | 40min |
| TLS captured but undecryptable | The client does not write out SSLKEYLOGFILE | Hook at the client process level (use Frida to capture ssl_read/ssl_write) to get plaintext | 1.5h |
| The data is correct but the server does not respond | The protocol carries an incrementing seq / nonce, so the replay is rejected | Work out how seq is computed (usually a hash of the previous frame or an incrementing counter) | 50min |

## Toolchain Findings

- **Wireshark Lua Dissector**: under 100 lines turns a proprietary protocol into something Wireshark can visualize
- **scapy**: for a Python parser, just define a `Packet` subclass
- **Kaitai Struct**: describe the protocol structure in YAML and generate parsers in multiple languages (Python/Java/C++/JS), good for long-term reuse
- **NetworkMiner** is better suited than Wireshark for "after the fact forensics" (automatic file reassembly, credential identification)
- **ent / binwalk -E** show entropy, above 7.5 it is almost certainly encrypted

## Key Code / Commands

scapy custom protocol example (TLV):

```python
from scapy.all import *

class MyMsg(Packet):
    name = "MyProto"
    fields_desc = [
        StrFixedLenField("magic", b"\xab\xcd", 2),
        ByteField("version", 1),
        ByteField("type", 0),
        LenField("length", None, fmt="H"),     # H = uint16 BE
        XIntField("seq", 0),
        StrLenField("payload", "", length_from=lambda p: p.length - 8),
        XShortField("crc", 0),
    ]

# Parse the PCAP
pkts = rdpcap('dump.pcap')
for p in pkts:
    if TCP in p and p[TCP].dport == 9527 and p.payload:
        msg = MyMsg(bytes(p[TCP].payload))
        msg.show()
```

Kaitai Struct YAML (the preferred option for long-running projects):

```yaml
# myproto.ksy
meta:
  id: myproto
  endian: be
seq:
  - id: magic
    contents: [0xab, 0xcd]
  - id: version
    type: u1
  - id: type
    type: u1
  - id: length
    type: u2
  - id: seq_no
    type: u4
  - id: payload
    size: length - 8
  - id: crc
    type: u2
```

Entropy analysis:

```bash
binwalk -E dump.bin             # Entropy graph
ent dump.bin                    # Numeric values
```

## Improvement Suggestions for This Package

- Add a "four-step method for custom protocol reversing" section to `reverse-engineering/platforms.md`
- Add a new quick reference at `reverse-engineering/references/kaitai-cheatsheet.md`
- Add scapy (pip) and binwalk to the bootstrap manifest

## Reusable Patterns / Script Snippets

**Four-step method for custom protocol reversing**:

```text
1. Study the rhythm (I/O graph + Conversations to find session boundaries)
2. Find the frame boundaries (magic / length / terminator)
3. Break out the fields (fixed header, length, payload, checksum)
4. Check for encryption (entropy + look for a nonce + cross-check the send function in the binary)
```

**A small trick for finding the frame length**:

Export every PSH packet from the same stream → look at each TCP segment's total length, and check whether a length field (try positions i, i+1, and i+2) can derive the segment length.

## Evolution Actions
- [ ] Add a protocol reversing section to reverse-engineering/platforms.md
- [ ] Add scapy / binwalk to bootstrap-manifest
- [ ] Add a Kaitai Struct quick reference

## Environment Information
- Kali / Ubuntu, Wireshark 4.x, Python 3.10+, scapy 2.5
- Target protocol: custom TCP binary (with TLV / length prefix)
- Encryption layer: depends on the case (commonly AES-CTR / ChaCha20)

## Redaction Requirements
This entry is seed data, written from publicly documented protocol reversing methods, and does not involve any real product.
