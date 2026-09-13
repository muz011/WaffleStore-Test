#!/bin/bash
# Download Apple SAP assets for WaffleStore
# This script downloads the required binaries from Apple's software update server
# and places them in the app bundle resources directory.

set -e

DOWNLOAD_URL="https://swcdn.apple.com/content/downloads/27/34/041-98128-A_SYPWICN3KH/5dqkl4rqgbsr18yzy61yeie9g3cmjc5hiv/OSXUpd10.9.pkg"
OUTPUT_DIR="./SAPAssets"
TEMP_DIR=$(mktemp -d)

echo "==> Downloading Apple software update package..."
curl -L -o "$TEMP_DIR/OSXUpd10.9.pkg" "$DOWNLOAD_URL"

echo "==> Extracting xar archive..."
cd "$TEMP_DIR"
xar -xf OSXUpd10.9.pkg

echo "==> Finding Payload..."
# The Payload is a bzip2-compressed cpio archive
# We need to find the right offset for the cpio data
PAYLOAD_FILE=$(find . -name "Payload" -type f | head -1)

if [ -z "$PAYLOAD_FILE" ]; then
    echo "ERROR: Payload not found in package"
    exit 1
fi

echo "==> Decompressing Payload..."
# Decompress the bzip2 data (skipping the first few bytes of the header)
# The offset 0x352F40D5 is specific to this package
python3 -c "
import bz2, sys
with open('$PAYLOAD_FILE', 'rb') as f:
    # Skip to the bzip2 data
    f.seek(0x352F40D5)
    data = f.read()
    decompressed = bz2.decompress(b'BZh9' + data)
    sys.stdout.buffer.write(decompressed)
" > payload.raw

echo "==> Extracting files from cpio archive..."
cd "$OUTPUT_DIR" 2>/dev/null || mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR"

# Extract required files from cpio
# The cpio data starts at offset 0x3A4 in the decompressed payload
dd if=payload.raw bs=1 skip=$((0x3A4)) 2>/dev/null | cpio -idm 2>/dev/null || true

echo "==> Copying required files..."
# Move files to output directory
REQUIRED_FILES=(
    "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/CommerceKit"
    "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Frameworks/CommerceCore.framework/Versions/A/CommerceCore"
    "./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP"
    "./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP.icxs"
)

NAMES=("CommerceKit" "CommerceCore" "CoreFP" "CoreFP_icxs")

for i in "${!REQUIRED_FILES[@]}"; do
    SRC="${REQUIRED_FILES[$i]}"
    DST="${NAMES[$i]}.bin"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$DST"
        echo "  -> $DST ($(wc -c < "$DST") bytes)"
    else
        echo "  WARNING: $SRC not found"
    fi
done

echo ""
echo "==> Done! Copy the .bin files to your WaffleStore app bundle resources."
echo "    Files needed: CommerceKit.bin, CommerceCore.bin, CoreFP.bin, CoreFP_icxs.bin"

# Cleanup
rm -rf "$TEMP_DIR"
