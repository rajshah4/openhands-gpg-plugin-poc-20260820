#!/bin/sh
set -eu

LOG_FILE=/tmp/openhands_gpg_gated.log

deny() {
  reason=$1
  printf '%s\n' "{\"decision\":\"deny\",\"reason\":\"GPG signing setup failed: $reason\"}"
  exit 2
}

if [ -z "${gpg_key:-}" ]; then
  deny "stored gpg_key secret is unavailable"
fi

export GPG_TTY=/dev/null
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

if ! printf '%s' "$gpg_key" | gpg --batch --import >>"$LOG_FILE" 2>&1; then
  deny "private-key import failed"
fi

KEY_ID=$(gpg --batch --with-colons --list-secret-keys 2>>"$LOG_FILE" |
  awk -F: '$1 == "sec" { want = 1; next } want && $1 == "fpr" { print $10; exit }')

if [ -z "$KEY_ID" ]; then
  deny "no secret signing key was found after import"
fi

git config --global user.signingkey "$KEY_ID"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.program gpg

printf '%s\n' "[gpg-signer] signing configured for $KEY_ID" >>"$LOG_FILE"
exit 0
