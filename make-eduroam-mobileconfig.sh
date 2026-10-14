#!/usr/bin/env bash
#
# make-eduroam-mobileconfig.sh
#
# Builds an Apple .mobileconfig profile for eduroam using EAP-TTLS / PAP
# (required for FreeRADIUS + Google Workspace Secure LDAP).
#
# The profile trusts the Let's Encrypt roots (ISRG Root X1, X2, YE, YR) and
# pins the RADIUS server name, so it keeps working through 60/90-day
# certificate renewals as long as the server name stays the same.
#
# Usage:
#   ./make-eduroam-mobileconfig.sh
#
# Works on Linux and macOS. Requires: curl, openssl, grep, tr.
# Optional: uuidgen, python3 or plutil (for validation).
#

set -euo pipefail

ROOTS_DIR="${ROOTS_DIR:-$HOME/eduroam-roots}"
OUT_DIR="${OUT_DIR:-$PWD}"

ROOT_URLS=(
  "isrgrootx1.pem|https://letsencrypt.org/certs/isrgrootx1.pem|ISRG Root X1"
  "isrg-root-x2.pem|https://letsencrypt.org/certs/isrg-root-x2.pem|ISRG Root X2"
  "root-ye.pem|https://letsencrypt.org/certs/gen-y/root-ye.pem|ISRG Root YE"
  "root-yr.pem|https://letsencrypt.org/certs/gen-y/root-yr.pem|ISRG Root YR"
)

# ---------- helpers ----------

die() { echo "ERROR: $*" >&2; exit 1; }

ask() {
  # ask "Prompt" "default" -> echoes answer
  local prompt="$1" default="${2:-}" answer
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " answer
    echo "${answer:-$default}"
  else
    while [[ -z "${answer:-}" ]]; do
      read -r -p "$prompt: " answer
    done
    echo "$answer"
  fi
}

new_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:lower:]' '[:upper:]'
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then
    tr '[:lower:]' '[:upper:]' < /proc/sys/kernel/random/uuid
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import uuid;print(str(uuid.uuid4()).upper())'
  else
    die "No way to generate UUIDs (install uuid-runtime or python3)."
  fi
}

xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
  s="${s//\"/&quot;}"; s="${s//\'/&apos;}"
  echo "$s"
}

slugify() {
  # "Paxton Public Schools" -> "paxton-public-schools"
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}

reverse_domain() {
  # paxtonschools.org -> org.paxtonschools
  echo "$1" | awk -F. '{for(i=NF;i>0;i--){printf "%s%s",$i,(i>1?".":"")}}'
}

b64_body() { grep -v '^-----' "$1" | tr -d '\r\n'; }

# ---------- prompts ----------

echo "=== eduroam .mobileconfig builder (EAP-TTLS / PAP) ==="
echo

SCHOOL_NAME=$(ask "School name (shown in profile, used for filename)")
REALM=$(ask "Realm (users sign in as user@REALM)")
REALM="${REALM#@}"
REALM=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')
[[ "$REALM" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || die "Realm '$REALM' doesn't look like a domain."

SERVER_NAME=$(ask "RADIUS server certificate name (CN/SAN)" "radius.$REALM")
SERVER_NAME=$(echo "$SERVER_NAME" | tr '[:upper:]' '[:lower:]')

SSID=$(ask "Wi-Fi SSID" "eduroam")
ANON=$(ask "Anonymous outer identity" "anonymous@$REALM")

# Optional: verify against the actual server certificate
read -r -p "Path to server cert to verify name (Enter to skip): " CERT_PATH || true
if [[ -n "$CERT_PATH" ]]; then
  if [[ -r "$CERT_PATH" ]]; then
    NAMES=$(openssl x509 -in "$CERT_PATH" -noout -subject -ext subjectAltName 2>/dev/null || true)
    if echo "$NAMES" | grep -qiF "$SERVER_NAME"; then
      echo "  OK: '$SERVER_NAME' found in certificate."
    else
      echo "  WARNING: '$SERVER_NAME' NOT found in certificate:"
      echo "$NAMES" | sed 's/^/    /'
      [[ "$(ask "Continue anyway? (y/n)" "n")" =~ ^[Yy] ]] || die "Aborted."
    fi
  else
    echo "  WARNING: cannot read $CERT_PATH (try running with sudo). Skipping check."
  fi
fi

SLUG=$(slugify "$SCHOOL_NAME")
[[ -n "$SLUG" ]] || die "School name produced an empty filename."
ID_BASE="$(reverse_domain "$REALM").eduroam"
OUT_FILE="$OUT_DIR/eduroam-$SLUG.mobileconfig"
SCHOOL_XML=$(xml_escape "$SCHOOL_NAME")

# ---------- root certificates ----------

mkdir -p "$ROOTS_DIR"
echo
echo "Checking root certificates in $ROOTS_DIR ..."
CERT_BLOCKS=""
ANCHORS=""
i=0
for entry in "${ROOT_URLS[@]}"; do
  IFS='|' read -r file url label <<< "$entry"
  path="$ROOTS_DIR/$file"
  if [[ ! -s "$path" ]]; then
    echo "  Downloading $label ..."
    curl -fsSL "$url" -o "$path" || die "Download failed: $url"
  fi
  subj=$(openssl x509 -in "$path" -noout -subject 2>/dev/null | sed 's/^subject= *//') \
    || die "$path is not a valid certificate."
  iss=$(openssl x509 -in "$path" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
  [[ "$subj" == "$iss" ]] || die "$path is not self-signed (subject != issuer)."
  echo "  OK: $label"

  uuid=$(new_uuid)
  i=$((i+1))
  CERT_BLOCKS+="
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${ID_BASE}.ca${i}</string>
      <key>PayloadUUID</key><string>${uuid}</string>
      <key>PayloadDisplayName</key><string>${label}</string>
      <key>PayloadContent</key><data>$(b64_body "$path")</data>
    </dict>"
  ANCHORS+="
          <string>${uuid}</string>"
done

# ---------- write profile ----------

PROFILE_UUID=$(new_uuid)
WIFI_UUID=$(new_uuid)

cat > "$OUT_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadDisplayName</key><string>eduroam - ${SCHOOL_XML}</string>
  <key>PayloadDescription</key><string>Configures ${SSID} Wi-Fi for ${SCHOOL_XML}. Sign in with your full school email (user@${REALM}) and password.</string>
  <key>PayloadOrganization</key><string>${SCHOOL_XML}</string>
  <key>PayloadIdentifier</key><string>${ID_BASE}</string>
  <key>PayloadUUID</key><string>${PROFILE_UUID}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadContent</key>
  <array>${CERT_BLOCKS}
    <dict>
      <key>PayloadType</key><string>com.apple.wifi.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${ID_BASE}.wifi</string>
      <key>PayloadUUID</key><string>${WIFI_UUID}</string>
      <key>PayloadDisplayName</key><string>${SSID} Wi-Fi</string>
      <key>SSID_STR</key><string>${SSID}</string>
      <key>HIDDEN_NETWORK</key><false/>
      <key>EncryptionType</key><string>WPA2</string>
      <key>AutoJoin</key><true/>
      <key>EAPClientConfiguration</key>
      <dict>
        <key>AcceptEAPTypes</key><array><integer>21</integer></array>
        <key>TTLSInnerAuthentication</key><string>PAP</string>
        <key>OuterIdentity</key><string>${ANON}</string>
        <key>TLSTrustedServerNames</key><array><string>${SERVER_NAME}</string></array>
        <key>PayloadCertificateAnchorUUID</key>
        <array>${ANCHORS}
        </array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
EOF

# ---------- validate ----------

echo
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$OUT_FILE"
elif command -v python3 >/dev/null 2>&1; then
  python3 -c "import plistlib,sys;plistlib.load(open(sys.argv[1],'rb'));print('Valid plist')" "$OUT_FILE"
else
  echo "(No plutil/python3 found; skipped plist validation.)"
fi

echo
echo "Created: $OUT_FILE"
echo "  School:      $SCHOOL_NAME"
echo "  Realm:       $REALM"
echo "  Server name: $SERVER_NAME"
echo "  SSID:        $SSID"
echo "  Outer ID:    $ANON"
echo
echo "Install on Mac: double-click the file, then System Settings > General >"
echo "Device Management > Install. Sign in as user@$REALM."
