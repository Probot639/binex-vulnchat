#!/usr/bin/env bash
#
# quickstart.sh - Setup helper for custom Kerberos implementation
#
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${SCRIPT_DIR}/keys"
CONFIG_DIR="${SCRIPT_DIR}/config"
DEFAULT_PORT=88   # traditional Kerberos KDC port; change if yours differs

# Realm and default enctype - override via env if you want, e.g.:
#   KRB_REALM=MYLAB.LOCAL ./quickstart.sh genkeys
REALM="${KRB_REALM:-EXAMPLE.COM}"
DEFAULT_ENCTYPE="aes256-cts-hmac-sha384-192"

MASTER_KEY_FILE="${KEYS_DIR}/master.key"
SAML_DIR="${SCRIPT_DIR}/saml"
SAML_SERVICES_DIR="${SAML_DIR}/services"
IDP_SIGNING_KEY_FILE="${SAML_DIR}/idp-signing.key"
IDP_SIGNING_CERT_FILE="${SAML_DIR}/idp-signing.crt"

# ---------------------------------------------------------------------------
# Usage / help
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <command> [arguments]

Commands:
  genkeys                     Generate the KDC master key and any long-term
                              service keys needed before clients can register.

  service NAME IP_ADDR[:PORT] [SP_CERT_FILE]
                              Register a service server (SAML SP) with this
                              IdP - e.g. the chat server clients get
                              redirected here from. IP_ADDR[:PORT] is where
                              the SP's ACS endpoint lives. SP_CERT_FILE is
                              optional: the SP's own public cert/PEM, used
                              to verify signed AuthnRequests from it.
                              Example: ${SCRIPT_NAME} service chat-server 10.0.0.20:8443
                                       ${SCRIPT_NAME} service chat-server 10.0.0.20:8443 ./chat-sp.pem

  (no command)                Show this help message.

EOF
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

require_dir() {
    local dir="$1"
    [[ -d "$dir" ]] || mkdir -p "$dir"
}

# Splits IP_ADDR[:PORT] into GLOBAL vars: PARSED_IP, PARSED_PORT
parse_addr() {
    local input="$1"
    if [[ "$input" == *:* ]]; then
        PARSED_IP="${input%%:*}"
        PARSED_PORT="${input##*:}"
    else
        PARSED_IP="$input"
        PARSED_PORT="$DEFAULT_PORT"
    fi

    # crude validation - adjust if you need hostname support, not just IPs
    if ! [[ "$PARSED_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        die "Invalid IP address: '${PARSED_IP}'"
    fi
    if ! [[ "$PARSED_PORT" =~ ^[0-9]+$ ]] || (( PARSED_PORT < 1 || PARSED_PORT > 65535 )); then
        die "Invalid port: '${PARSED_PORT}'"
    fi
}

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------
# NOTE: This is a scaffold to illustrate the *shape* of key storage
# (principal / kvno / enctype / timestamp, key encrypted under a master
# key) - not an audited crypto implementation. Swap in a real crypto
# library (not shell-out openssl) before this touches anything you
# actually care about.

require_openssl() {
    command -v openssl >/dev/null 2>&1 || die "openssl is required but not found in PATH."
}

# Generates the KDC master key on first run. This key encrypts every
# other key at rest, so it gets stricter handling than the rest:
#   - generated once, never regenerated silently
#   - file perms locked to 600
#   - in a real deployment this is usually stashed separately from the
#     principal database, or entered manually at KDC startup instead
#     of living on disk at all
ensure_master_key() {
    require_dir "$KEYS_DIR"

    if [[ -f "$MASTER_KEY_FILE" ]]; then
        log "Master key already present at ${MASTER_KEY_FILE} (leaving it alone)."
        return
    fi

    log "Generating new KDC master key ..."
    umask 077
    openssl rand -hex 32 > "$MASTER_KEY_FILE"
    chmod 600 "$MASTER_KEY_FILE"
    log "Master key written to ${MASTER_KEY_FILE} (mode 600)."
}

# Encrypts a hex-encoded key under the master key (AES-256-CBC, random
# IV per call). Echoes "iv_hex ciphertext_b64" on stdout.
#
# This is here to show *where* encryption-at-rest belongs in the flow,
# not as a template for production AEAD - move to a real library and
# an authenticated mode before this matters for real.
encrypt_key_material() {
    local plaintext_hex="$1"
    local master_hex
    master_hex="$(<"$MASTER_KEY_FILE")"

    local iv_hex
    iv_hex="$(openssl rand -hex 16)"

    local ciphertext_b64
    ciphertext_b64="$(printf '%s' "$plaintext_hex" \
        | openssl enc -aes-256-cbc -K "$master_hex" -iv "$iv_hex" -base64 -A)"

    printf '%s %s' "$iv_hex" "$ciphertext_b64"
}

# Writes one principal's key record as JSON to keys/<slug>.json.
#   $1 = principal name (e.g. krbtgt/REALM@REALM)
#   $2 = kvno
#   $3 = enctype
write_key_record() {
    local principal="$1" kvno="$2" enctype="$3"
    local slug timestamp raw_key_hex enc_result iv_hex ciphertext_b64 out_file

    slug="$(printf '%s' "$principal" | tr '/@:' '___')"
    out_file="${KEYS_DIR}/${slug}.json"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Raw key bytes for the principal. 32 bytes is right for
    # aes256-cts-hmac-sha384-192's base encryption key; adjust if you
    # change DEFAULT_ENCTYPE to something with a different key size.
    raw_key_hex="$(openssl rand -hex 32)"

    enc_result="$(encrypt_key_material "$raw_key_hex")"
    iv_hex="${enc_result%% *}"
    ciphertext_b64="${enc_result#* }"

    cat > "$out_file" <<EOF
{
  "principal": "${principal}",
  "kvno": ${kvno},
  "enctype": "${enctype}",
  "timestamp": "${timestamp}",
  "key_iv_hex": "${iv_hex}",
  "key_ciphertext_b64": "${ciphertext_b64}"
}
EOF
    chmod 600 "$out_file"
    log "Wrote key record for ${principal} -> ${out_file}"
}

cmd_genkeys() {
    require_openssl
    require_dir "$KEYS_DIR"

    ensure_master_key

    # krbtgt is the TGS's own key - it signs/encrypts every TGT issued
    # for this realm, so it needs to exist before anything else can
    # authenticate. kvno starts at 1; bump this and re-run key
    # generation (not regeneration of the same record) when rotating.
    local krbtgt_principal="krbtgt/${REALM}@${REALM}"
    write_key_record "$krbtgt_principal" 1 "$DEFAULT_ENCTYPE"

    log "Key generation complete for realm ${REALM}."
}



# ---------------------------------------------------------------------------
# SAML service (SP) registration
# ---------------------------------------------------------------------------
# Same disclaimer as the key-generation section: this shows the *shape*
# of IdP-side SP registration, not a hardened SAML implementation.
# Signing/parsing of actual SAML XML (or whatever your custom Kerberos
# implementation swaps in for the assertion format) is not here - only
# the bookkeeping of who's registered and what their trust material is.

# Generates the IdP's own signing key/cert on first run. Every SAML
# assertion this IdP issues - regardless of which SP it's for - gets
# signed with this one key, so it's IdP-wide, not per-SP. Analogous to
# the krbtgt key on the Kerberos side: one long-lived identity for the
# IdP itself.
ensure_idp_signing_key() {
    require_dir "$SAML_DIR"

    if [[ -f "$IDP_SIGNING_KEY_FILE" && -f "$IDP_SIGNING_CERT_FILE" ]]; then
        log "IdP signing key/cert already present in ${SAML_DIR} (leaving them alone)."
        return
    fi

    log "Generating new IdP SAML signing key + self-signed cert ..."
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
        -keyout "$IDP_SIGNING_KEY_FILE" \
        -out "$IDP_SIGNING_CERT_FILE" \
        -subj "/CN=${REALM} IdP" >/dev/null 2>&1
    chmod 600 "$IDP_SIGNING_KEY_FILE"
    log "IdP signing key -> ${IDP_SIGNING_KEY_FILE}"
    log "IdP signing cert -> ${IDP_SIGNING_CERT_FILE} (give this to SPs so they can verify our assertions)"
}

# Writes one SP's registration record as JSON to saml/services/<slug>.json.
#   $1 = service name (e.g. chat-server)
#   $2 = ACS host/IP
#   $3 = ACS port
#   $4 = optional path to the SP's own public cert/PEM
write_service_record() {
    local name="$1" acs_ip="$2" acs_port="$3" sp_cert_path="${4:-}"
    local slug entity_id acs_url timestamp out_file
    local sp_cert_fingerprint="null"

    slug="$(printf '%s' "$name" | tr -c 'A-Za-z0-9_-' '_')"
    out_file="${SAML_SERVICES_DIR}/${slug}.json"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Entity ID and ACS URL are guesses at a convention - adjust to
    # whatever your chat server/SP actually expects to be called and
    # whatever path it listens for the assertion POST on.
    entity_id="urn:${REALM,,}:sp:${slug}"
    acs_url="https://${acs_ip}:${acs_port}/saml/acs"

    if [[ -n "$sp_cert_path" ]]; then
        [[ -f "$sp_cert_path" ]] || die "SP cert file not found: ${sp_cert_path}"
        sp_cert_fingerprint="\"$(openssl x509 -in "$sp_cert_path" -noout -fingerprint -sha256 \
            | sed -E 's/^.*Fingerprint=//')\""
    else
        warn "No SP cert provided - AuthnRequests from this SP won't be signature-verified."
        warn "Re-run with the SP's cert path once you have one, e.g.:"
        warn "  ${SCRIPT_NAME} service ${name} ${acs_ip}:${acs_port} /path/to/${slug}.pem"
    fi

    require_dir "$SAML_SERVICES_DIR"
    cat > "$out_file" <<EOF
{
  "service_name": "${name}",
  "entity_id": "${entity_id}",
  "acs_url": "${acs_url}",
  "registered_at": "${timestamp}",
  "sp_cert_sha256_fingerprint": ${sp_cert_fingerprint}
}
EOF
    log "Wrote SP registration for ${name} -> ${out_file}"
    log "  entity_id: ${entity_id}"
    log "  acs_url:   ${acs_url}"
}

cmd_service() {
    local name="${1:-}" addr="${2:-}" sp_cert_path="${3:-}"

    [[ -n "$name" ]] || { warn "Missing NAME argument."; usage; exit 1; }
    [[ -n "$addr" ]] || { warn "Missing IP_ADDR[:PORT] argument."; usage; exit 1; }

    parse_addr "$addr"

    require_openssl
    ensure_idp_signing_key
    write_service_record "$name" "$PARSED_IP" "$PARSED_PORT" "$sp_cert_path"

    log "Service '${name}' registered. Give it ${IDP_SIGNING_CERT_FILE} so it can verify our assertions."
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
main() {
    local cmd="${1:-}"

    case "$cmd" in
        "")
            usage
            ;;
        genkeys)
            cmd_genkeys
            ;;
        service)
            shift
            cmd_service "$@"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            warn "Unknown command: '${cmd}'"
            usage
            exit 1
            ;;
    esac
}

main "$@"