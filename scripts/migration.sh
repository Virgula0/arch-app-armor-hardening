#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-/etc/ssh-guard/config}"
KEYFILE="/etc/ssh-guard/fscrypt.key"
SSH_GUARD_BIN="/usr/local/sbin/ssh-guard"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if ! command -v fscrypt &> /dev/null; then
    echo "ERROR: 'fscrypt' not installed. Install with: sudo pacman -S fscrypt" >&2
    exit 1
fi

# --- Ensure fscrypt system‑wide setup ---
if [[ ! -f /etc/fscrypt.conf ]]; then
    echo "Setting up fscrypt system-wide..."
    fscrypt setup
fi

# --- Ensure master key exists (32 bytes) ---
if [[ ! -f "$KEYFILE" ]]; then
    echo "Master key not found. Generating with ssh-guard --genkey..."
    "$SSH_GUARD_BIN" --genkey
fi

# Validate key size
KEY_SIZE=$(stat -c%s "$KEYFILE")
if [[ "$KEY_SIZE" -ne 32 ]]; then
    echo "ERROR: $KEYFILE must be exactly 32 bytes, but is $KEY_SIZE bytes." >&2
    echo "Delete it and let this script regenerate it." >&2
    exit 1
fi

# --- Parse watched directories ---
mapfile -t dirs < <(
    awk -F'[][]' '/^\[watch / {print $2}' "$CONFIG" | awk '{print $2}'
)

if [[ ${#dirs[@]} -eq 0 ]]; then
    echo "No [watch] entries found in $CONFIG."
    exit 1
fi

echo "Found ${#dirs[@]} directory(ies) to encrypt."

for dir in "${dirs[@]}"; do
    if [[ ! -d "$dir" ]]; then
        echo "SKIP: $dir does not exist."
        continue
    fi

    # Already encrypted?
    if fscrypt status "$dir" 2>/dev/null | grep -q "Unlocked: Yes"; then
        echo "SKIP: $dir is already encrypted."
        continue
    fi

    echo ">>> Encrypting $dir ..."

    # Temporarily remove immutable/append-only flags (if any)
    echo "Removing immutable flags from $dir..."
    chattr -R -i -a "$dir" 2>/dev/null || true

    tmpdir="${dir}.new"
    rm -rf "$tmpdir"
    mkdir "$tmpdir"
    chmod --reference="$dir" "$tmpdir"
    chown --reference="$dir" "$tmpdir"

    # Unique protector name per directory to avoid collisions
    PROT_NAME="ssh-guard-key-$(date +%s%N)"
    fscrypt encrypt "$tmpdir" \
        --source=raw_key \
        --key="$KEYFILE" \
        --name="$PROT_NAME"

    # Copy all contents (kernel encrypts on the fly)
    cp -aT "$dir" "$tmpdir"

    # Securely delete original unencrypted files
    find "$dir" -type f -print0 | xargs -0 shred -n1 --remove=unlink 2>/dev/null || true

    rm -rf "$dir"
    mv "$tmpdir" "$dir"

    echo "<<< $dir is now encrypted."
done

echo "Migration finished."