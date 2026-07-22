#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${DUSHENG_SERVICE_NAME:-dusheng-agent}"
DPI_SERVICE_NAME="${DUSHENG_DPI_SERVICE_NAME:-dusheng-dpi}"
INSTALL_DIR="${DUSHENG_INSTALL_DIR:-/opt/dusheng-agent}"
CONFIG_DIR="${DUSHENG_CONFIG_DIR:-/etc/dusheng}"
DATA_DIR="${DUSHENG_DATA_DIR:-/var/lib/dusheng-agent}"
LOG_DIR="${DUSHENG_LOG_DIR:-/var/log/dusheng-agent}"
AGENT_USER="${DUSHENG_AGENT_USER:-dusheng-agent}"
RELEASE_BASE="${DUSHENG_RELEASE_BASE:-https://github.com/SatanDS/DuSheng-Panel/releases/latest/download}"
AGENT_URL="${DUSHENG_AGENT_URL:-}"
AGENT_SHA256="${DUSHENG_AGENT_SHA256:-}"
CHECKSUMS_URL="${DUSHENG_CHECKSUMS_URL:-${RELEASE_BASE}/checksums.txt}"
SKIP_VERIFY="${DUSHENG_SKIP_VERIFY:-0}"
DOWNLOAD_CONNECT_TIMEOUT="${DUSHENG_DOWNLOAD_CONNECT_TIMEOUT:-15}"
DOWNLOAD_MAX_TIME="${DUSHENG_DOWNLOAD_MAX_TIME:-1800}"
DOWNLOAD_RETRIES="${DUSHENG_DOWNLOAD_RETRIES:-5}"
GOST_URL="${DUSHENG_GOST_URL:-}"
GOST_BIN="${DUSHENG_GOST_PATH:-${DUSHENG_GOST_BIN:-/usr/local/bin/gost}}"
DPI_ENABLED="${DUSHENG_DPI_ENABLED:-1}"
DPI_ADDR="${DUSHENG_DPI_ADDR:-unix:/run/dusheng-dpi/dpi.sock}"
DPI_ENGINE="${DUSHENG_DPI_ENGINE:-auto}"
DPI_MAX_FLOWS="${DUSHENG_DPI_MAX_FLOWS:-8192}"
DPI_FLOW_TTL="${DUSHENG_DPI_FLOW_TTL:-2m}"
DPI_MAX_PACKETS="${DUSHENG_DPI_MAX_PACKETS:-12}"
METRICS_LISTEN="${DUSHENG_METRICS_LISTEN-127.0.0.1:19090}"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must run as root. Re-run with sudo." >&2
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required." >&2
    exit 1
  fi
}

detect_os() {
  if [ ! -r /etc/os-release ]; then
    echo "Cannot detect operating system: /etc/os-release is missing." >&2
    exit 1
  fi

  # /etc/os-release is provided by every supported distribution.
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian)
      case "${VERSION_ID:-}" in
        11|12|13) ;;
        *) echo "Unsupported Debian version: ${VERSION_ID:-unknown}. Debian 11, 12, or 13 is required." >&2; exit 1 ;;
      esac
      ;;
    ubuntu)
      local major
      major="${VERSION_ID:-0}"
      major="${major%%.*}"
      if [ "${major:-0}" -lt 22 ]; then
        echo "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Ubuntu 22.04 or newer is required." >&2
        exit 1
      fi
      ;;
    *)
      echo "Unsupported OS: ${ID:-unknown}. Use Debian 11, Debian 12, or Ubuntu 22.04+." >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "Unsupported architecture: $(uname -m). amd64 or arm64 is required." >&2; exit 1 ;;
  esac
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  local packages=(ca-certificates curl tar gzip)
  if ! command -v systemctl >/dev/null 2>&1; then
    packages+=(systemd)
  fi
  apt-get update
  apt-get install -y --no-install-recommends "${packages[@]}"
}

ensure_user_and_dirs() {
  if ! getent group "$AGENT_USER" >/dev/null 2>&1; then
    groupadd --system "$AGENT_USER"
  fi
  if ! id "$AGENT_USER" >/dev/null 2>&1; then
    useradd --system --gid "$AGENT_USER" --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$AGENT_USER"
  fi

  install -d -m 0755 "$INSTALL_DIR" "$CONFIG_DIR"
  install -d -m 0750 -o "$AGENT_USER" -g "$AGENT_USER" "$DATA_DIR" "$LOG_DIR"
}

download_file() {
  local url="$1"
  local dest="$2"
  echo "Downloading ${url}..."
  # GitHub release downloads can be slow or intermittently reset in some regions.
  # Keep partial data across curl retries and prefer HTTP/1.1 to avoid broken HTTP/2 streams.
  curl --fail --show-error --location --http1.1 \
    --retry "$DOWNLOAD_RETRIES" --retry-all-errors --retry-delay 3 \
    --connect-timeout "$DOWNLOAD_CONNECT_TIMEOUT" --max-time "$DOWNLOAD_MAX_TIME" \
    --continue-at - --output "$dest" "$url"
}

verify_agent_archive() {
  local archive="$1"
  local asset_name="$2"
  if [ "$SKIP_VERIFY" = "1" ]; then
    echo "WARNING: agent checksum verification was explicitly disabled." >&2
    return
  fi
  local expected="$AGENT_SHA256"
  if [ -z "$expected" ]; then
    local checksum_file
    checksum_file="$(mktemp)"
    if ! download_file "$CHECKSUMS_URL" "$checksum_file"; then
      rm -f "$checksum_file"
      echo "Unable to download release checksums from $CHECKSUMS_URL." >&2
      echo "Set DUSHENG_AGENT_SHA256 explicitly, or use DUSHENG_SKIP_VERIFY=1 only for trusted development builds." >&2
      exit 1
    fi
    expected="$(awk -v name="$asset_name" '$2 == name { print $1; exit }' "$checksum_file")"
    rm -f "$checksum_file"
  fi
  if ! printf '%s' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    echo "No valid SHA256 checksum was found for $asset_name." >&2
    exit 1
  fi
  local actual
  actual="$(sha256sum "$archive" | awk '{print $1}')"
  if [ "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" != "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ]; then
    echo "SHA256 verification failed for $asset_name." >&2
    exit 1
  fi
  echo "Verified SHA256 for $asset_name"
}

install_dpi_support_files() {
  local base_dir="$1"
  local lib_dir="${DUSHENG_DPI_LIB_DIR:-$base_dir/dusheng-dpi-lib}"
  if [ -d "$lib_dir" ]; then
    rm -rf "$INSTALL_DIR/dusheng-dpi-lib"
    install -d -m 0755 "$INSTALL_DIR/dusheng-dpi-lib"
    cp -a "$lib_dir/." "$INSTALL_DIR/dusheng-dpi-lib/"
  fi
  if [ -f "$base_dir/THIRD_PARTY_NOTICES.md" ]; then
    install -m 0644 "$base_dir/THIRD_PARTY_NOTICES.md" "$INSTALL_DIR/THIRD_PARTY_NOTICES.md"
  fi
}

install_agent_binary() {
  local arch="$1"
  local tmp
  tmp="$(mktemp -d)"

  if [ -n "${DUSHENG_AGENT_BINARY:-}" ]; then
    install -m 0755 "$DUSHENG_AGENT_BINARY" "$INSTALL_DIR/dusheng-agent"
    if [ "$DPI_ENABLED" != "0" ] && [ -n "${DUSHENG_DPI_BINARY:-}" ]; then
      install -m 0755 "$DUSHENG_DPI_BINARY" "$INSTALL_DIR/dusheng-dpi"
      install_dpi_support_files "$(dirname "$DUSHENG_DPI_BINARY")"
    fi
  elif [ -x ./dusheng-agent ]; then
    install -m 0755 ./dusheng-agent "$INSTALL_DIR/dusheng-agent"
    if [ "$DPI_ENABLED" != "0" ] && [ -x ./dusheng-dpi ]; then
      install -m 0755 ./dusheng-dpi "$INSTALL_DIR/dusheng-dpi"
      install_dpi_support_files "."
    fi
  else
    if [ -z "$AGENT_URL" ]; then
      AGENT_URL="$RELEASE_BASE/dusheng-agent-linux-$arch.tar.gz"
    fi
    echo "Downloading DuSheng agent from $AGENT_URL"
    download_file "$AGENT_URL" "$tmp/agent"
    verify_agent_archive "$tmp/agent" "dusheng-agent-linux-$arch.tar.gz"
    if tar -tzf "$tmp/agent" >/dev/null 2>&1; then
      tar -xzf "$tmp/agent" -C "$tmp"
      local found
      found="$(find "$tmp" -type f -name dusheng-agent | head -n 1)"
      if [ -z "$found" ]; then
        echo "Archive does not contain a file named dusheng-agent." >&2
        exit 1
      fi
      install -m 0755 "$found" "$INSTALL_DIR/dusheng-agent"
      if [ "$DPI_ENABLED" != "0" ]; then
        local dpi_found
        dpi_found="$(find "$tmp" -type f -name dusheng-dpi | head -n 1)"
        if [ -n "$dpi_found" ]; then
          install -m 0755 "$dpi_found" "$INSTALL_DIR/dusheng-dpi"
          install_dpi_support_files "$(dirname "$dpi_found")"
        else
          echo "Archive does not contain dusheng-dpi; DPI sidecar will be disabled." >&2
        fi
      fi
    else
      install -m 0755 "$tmp/agent" "$INSTALL_DIR/dusheng-agent"
    fi
  fi

  chown root:root "$INSTALL_DIR/dusheng-agent"
  if [ -x "$INSTALL_DIR/dusheng-dpi" ]; then
    chown root:root "$INSTALL_DIR/dusheng-dpi"
    if [ -d "$INSTALL_DIR/dusheng-dpi-lib" ]; then
      chown -R root:root "$INSTALL_DIR/dusheng-dpi-lib"
    fi
  fi
  rm -rf "$tmp"
}

install_gost_binary() {
  if [ -x "$GOST_BIN" ]; then
    return
  fi
  if [ -z "$GOST_URL" ]; then
    echo "gost was not found at $GOST_BIN. Set DUSHENG_GOST_URL to install it automatically." >&2
    return
  fi

  local tmp
  tmp="$(mktemp -d)"
  echo "Downloading gost from $GOST_URL"
  install -d -m 0755 "$(dirname "$GOST_BIN")"
  download_file "$GOST_URL" "$tmp/gost"
  if tar -tzf "$tmp/gost" >/dev/null 2>&1; then
    tar -xzf "$tmp/gost" -C "$tmp"
    local found
    found="$(find "$tmp" -type f -name gost | head -n 1)"
    if [ -z "$found" ]; then
      echo "gost archive does not contain a file named gost." >&2
      exit 1
    fi
    install -m 0755 "$found" "$GOST_BIN"
  else
    install -m 0755 "$tmp/gost" "$GOST_BIN"
  fi
  rm -rf "$tmp"
}

write_env_file() {
  local dpi_env=""
  if [ "$DPI_ENABLED" != "0" ] && [ -x "$INSTALL_DIR/dusheng-dpi" ]; then
    dpi_env="$DPI_ADDR"
  fi
  umask 077
  cat > "$CONFIG_DIR/agent.env" <<EOF
DUSHENG_API_URL=${DUSHENG_API_URL}
DUSHENG_INSTALL_TOKEN=${DUSHENG_INSTALL_TOKEN}
DUSHENG_DATA_DIR=${DATA_DIR}
DUSHENG_GOST_PATH=${GOST_BIN}
DUSHENG_GOST_BIN=${GOST_BIN}
DUSHENG_DPI_ADDR=${dpi_env}
DUSHENG_METRICS_LISTEN=${METRICS_LISTEN}
EOF
  chown root:"$AGENT_USER" "$CONFIG_DIR/agent.env"
}

write_uninstall_helper() {
  cat > "$INSTALL_DIR/uninstall-agent.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

MARKER="${DATA_DIR}/uninstall-requested"
if [ ! -f "\$MARKER" ]; then
  exit 0
fi

echo "DuSheng agent uninstall marker found; scheduling local agent cleanup."
API_URL=""
NODE_TOKEN=""
COMMAND_ID=""
if [ -f "${CONFIG_DIR}/agent.env" ]; then
  # shellcheck disable=SC1091
  . "${CONFIG_DIR}/agent.env"
  API_URL="\${DUSHENG_API_URL:-}"
fi
if [ -f "\$MARKER" ]; then
  COMMAND_ID="\$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "\$MARKER" | head -n 1)"
fi
if [ -f "${DATA_DIR}/node-credentials.json" ]; then
  NODE_TOKEN="\$(sed -n 's/.*"nodeToken"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${DATA_DIR}/node-credentials.json" | head -n 1)"
fi
CLEANUP="/tmp/${SERVICE_NAME}-cleanup.sh"
cat > "\$CLEANUP" <<CLEANUP_EOF
#!/usr/bin/env bash
set -u

API_URL="\${API_URL}"
NODE_TOKEN="\${NODE_TOKEN}"
COMMAND_ID="\${COMMAND_ID}"

systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl stop "${DPI_SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl disable "${DPI_SERVICE_NAME}" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
rm -f "/etc/systemd/system/${DPI_SERVICE_NAME}.service"
rm -f "${CONFIG_DIR}/agent.env"
rmdir "${CONFIG_DIR}" >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl reset-failed "${DPI_SERVICE_NAME}" >/dev/null 2>&1 || true
if [ -n "\$API_URL" ] && [ -n "\$NODE_TOKEN" ] && [ -n "\$COMMAND_ID" ] && command -v curl >/dev/null 2>&1; then
  curl -fsS -X POST "\${API_URL%/}/api/v1/agent/commands/\${COMMAND_ID}/ack" \
    -H "Authorization: Bearer \$NODE_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"status":"done","message":"local cleanup completed"}' >/dev/null 2>&1 || true
fi
rm -rf "${DATA_DIR}" "${LOG_DIR}" "${INSTALL_DIR}" >/dev/null 2>&1 || true
rm -f "\$0" >/dev/null 2>&1 || true
CLEANUP_EOF
chmod 0755 "\$CLEANUP"

if command -v systemd-run >/dev/null 2>&1; then
  if ! systemd-run --unit "${SERVICE_NAME}-cleanup" --on-active=2s /bin/bash "\$CLEANUP" >/dev/null 2>&1; then
    nohup /bin/bash "\$CLEANUP" >/dev/null 2>&1 &
  fi
else
  nohup /bin/bash "\$CLEANUP" >/dev/null 2>&1 &
fi
EOF
  chmod 0755 "$INSTALL_DIR/uninstall-agent.sh"
  chown root:root "$INSTALL_DIR/uninstall-agent.sh"
}

write_service() {
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=DuSheng Panel node agent
Documentation=https://github.com/SatanDS/DuSheng-Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=DUSHENG_DATA_DIR=${DATA_DIR}
Environment=DUSHENG_GOST_PATH=${GOST_BIN}
Environment=DUSHENG_GOST_BIN=${GOST_BIN}
Environment=DUSHENG_DPI_ADDR=${DPI_ADDR}
Environment=DUSHENG_METRICS_LISTEN=${METRICS_LISTEN}
EnvironmentFile=-${CONFIG_DIR}/agent.env
ExecStart=${INSTALL_DIR}/dusheng-agent -base-url \${DUSHENG_API_URL} -data-dir \${DUSHENG_DATA_DIR} -gost-path \${DUSHENG_GOST_PATH} -dpi-addr \${DUSHENG_DPI_ADDR}
ExecStopPost=+/bin/bash ${INSTALL_DIR}/uninstall-agent.sh
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR} ${INSTALL_DIR} ${CONFIG_DIR} /etc/systemd/system

[Install]
WantedBy=multi-user.target
EOF
}

write_dpi_service() {
  if [ "$DPI_ENABLED" = "0" ] || [ ! -x "$INSTALL_DIR/dusheng-dpi" ]; then
    return
  fi
  cat > "/etc/systemd/system/${DPI_SERVICE_NAME}.service" <<EOF
[Unit]
Description=DuSheng Panel DPI sidecar
Documentation=https://github.com/SatanDS/DuSheng-Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_USER}
WorkingDirectory=${INSTALL_DIR}
RuntimeDirectory=dusheng-dpi
RuntimeDirectoryMode=0750
Environment=DUSHENG_DPI_ENGINE=${DPI_ENGINE}
Environment=DUSHENG_DPI_MAX_FLOWS=${DPI_MAX_FLOWS}
Environment=DUSHENG_DPI_FLOW_TTL=${DPI_FLOW_TTL}
Environment=DUSHENG_DPI_MAX_PACKETS=${DPI_MAX_PACKETS}
ExecStart=${INSTALL_DIR}/dusheng-dpi -listen ${DPI_ADDR} -engine \${DUSHENG_DPI_ENGINE} -max-flows \${DUSHENG_DPI_MAX_FLOWS} -flow-ttl \${DUSHENG_DPI_FLOW_TTL} -max-packets \${DUSHENG_DPI_MAX_PACKETS}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/run/dusheng-dpi

[Install]
WantedBy=multi-user.target
EOF
}

main() {
  need_root
  require_env DUSHENG_API_URL
  require_env DUSHENG_INSTALL_TOKEN
  detect_os
  local arch
  arch="$(detect_arch)"

  install_packages
  ensure_user_and_dirs
  install_agent_binary "$arch"
  install_gost_binary
  write_env_file
  write_uninstall_helper
  write_dpi_service
  write_service

  systemctl daemon-reload
  if [ "$DPI_ENABLED" != "0" ] && [ -x "$INSTALL_DIR/dusheng-dpi" ]; then
    systemctl enable "$DPI_SERVICE_NAME"
    systemctl restart "$DPI_SERVICE_NAME"
  fi
  systemctl enable "$SERVICE_NAME"
  if [ "${DUSHENG_NO_START:-0}" = "1" ]; then
    echo "Installed ${SERVICE_NAME}. Start it with: systemctl start ${SERVICE_NAME}"
  else
    systemctl restart "$SERVICE_NAME"
    echo "Installed and started ${SERVICE_NAME}."
  fi
}

main "$@"
