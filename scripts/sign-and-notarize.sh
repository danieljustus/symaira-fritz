#!/usr/bin/env bash
set -euo pipefail

os="${1:?missing target OS}"
binary="${2:?missing binary path}"

if [[ "$os" != "darwin" ]]; then
  exit 0
fi

required=(CODESIGN_IDENTITY NOTARY_API_KEY NOTARY_API_KEY_ID NOTARY_API_ISSUER)
missing=()
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    missing+=("$name")
  fi
done

if (( ${#missing[@]} > 0 )); then
  if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    printf 'Missing required release credentials: %s\n' "${missing[*]}" >&2
    exit 1
  fi
  printf 'Skipping local signing/notarization for %s (credentials unavailable).\n' "$binary"
  exit 0
fi

work_dir="$(mktemp -d)"
key_file="$work_dir/notary-api-key.p8"
zip_file="$work_dir/$(basename "$binary").zip"
result_file="$work_dir/notary-result.json"
trap 'rm -rf "$work_dir"' EXIT

if printf '%s' "$NOTARY_API_KEY" | openssl base64 -d -A > "$key_file" 2>/dev/null \
  && openssl pkey -in "$key_file" -noout >/dev/null 2>&1; then
  :
else
  printf '%s' "$NOTARY_API_KEY" > "$key_file"
  openssl pkey -in "$key_file" -noout >/dev/null
fi
chmod 600 "$key_file"

codesign --force --sign "$CODESIGN_IDENTITY" --timestamp --options runtime "$binary"
codesign --verify --strict --verbose=2 "$binary"

ditto -c -k --keepParent "$binary" "$zip_file"
xcrun notarytool submit "$zip_file" \
  --key "$key_file" \
  --key-id "$NOTARY_API_KEY_ID" \
  --issuer "$NOTARY_API_ISSUER" \
  --wait --output-format json > "$result_file"

status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$result_file")"
if [[ "$status" != "Accepted" ]]; then
  printf 'Notarization failed for %s: status=%s\n' "$binary" "$status" >&2
  exit 1
fi

# `stapler` supports bundles, disk images, and installer packages, but not a
# standalone Mach-O CLI binary. The submitted zip is the notarized artifact;
# attempting to staple the extracted binary returns Apple's error 73.
case "$binary" in
  *.app|*.dmg|*.pkg)
    staple_ok=0
    for attempt in 1 2 3; do
      if xcrun stapler staple "$binary" 2>/dev/null; then
        staple_ok=1
        break
      fi
      printf 'Staple attempt %d/3 failed for %s; retrying...\n' "$attempt" "$binary" >&2
      sleep 5
    done
    if [[ "$staple_ok" != 1 ]] || ! xcrun stapler validate "$binary" >/dev/null 2>&1; then
      printf 'Stapling failed for %s\n' "$binary" >&2
      exit 1
    fi
    printf 'Signed, notarized, and stapled %s\n' "$binary"
    ;;
  *)
    printf 'Signed and notarized standalone CLI binary %s (stapling is unsupported for this artifact type)\n' "$binary"
    ;;
esac