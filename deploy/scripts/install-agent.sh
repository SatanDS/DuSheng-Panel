#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${DUSHENG_SERVICE_NAME:-dusheng-agent}"
INSTALL_DIR="${DUSHENG_INSTALL_DIR:-/opt/dusheng-agent}"
CONFIG_DIR="${DUSHENG_CONFIG_DIR:-/etc/dusheng}"
DATA_DIR="${DUSHENG_DATA_DIR:-/var/lib/dusheng-agent}"
LOG_DIR="${DUSHENG_LOG_DIR:-/var/log/dusheng-agent}"
AGENT_USER="${DUSHENG_AGENT_USER:-dusheng-agent}"
RELEASE_BASE="${DUSHENG_RELEASE_BASE:-https://github.com/SatanDS/DuSheng-Panel/releases/latest/download}"
AGENT_URL="${DUSHENG_AGENT_URL:-}"
GOST_URL="${DUSHENG_GOST_URL:-}"
GOST_BIN="${DUSHENG_GOST_PATH:-${DUSHENG_GOST_BIN:-/usr/local/bin/gost}}"

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
  curl -fL --retry 3 --connect-timeout 10 -o "$dest" "$url"
}

install_agent_binary() {
  local arch="$1"
  local tmp
  tmp="$(mktemp -d)"

  if [ -n "${DUSHENG_AGENT_BINARY:-}" ]; then
    install -m 0755 "$DUSHENG_AGENT_BINARY" "$INSTALL_DIR/dusheng-agent"
  elif [ -x ./dusheng-agent ]; then
    install -m 0755 ./dusheng-agent "$INSTALL_DIR/dusheng-agent"
  else
    if [ -z "$AGENT_URL" ]; then
      AGENT_URL="$RELEASE_BASE/dusheng-agent-linux-$arch.tar.gz"
    fi
    echo "Downloading DuSheng agent from $AGENT_URL"
    download_file "$AGENT_URL" "$tmp/agent"
    if tar -tzf "$tmp/agent" >/dev/null 2>&1; then
      tar -xzf "$tmp/agent" -C "$tmp"
      local found
      found="$(find "$tmp" -type f -name dusheng-agent | head -n 1)"
      if [ -z "$found" ]; then
        echo "Archive does not contain a file named dusheng-agent." >&2
        exit 1
      fi
      install -m 0755 "$found" "$INSTALL_DIR/dusheng-agent"
    else
      install -m 0755 "$tmp/agent" "$INSTALL_DIR/dusheng-agent"
    fi
  fi

  chown root:root "$INSTALL_DIR/dusheng-agent"
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
  umask 077
  cat > "$CONFIG_DIR/agent.env" <<EOF
DUSHENG_API_URL=${DUSHENG_API_URL}
DUSHENG_INSTALL_TOKEN=${DUSHENG_INSTALL_TOKEN}
DUSHENG_DATA_DIR=${DATA_DIR}
DUSHENG_GOST_PATH=${GOST_BIN}
DUSHENG_GOST_BIN=${GOST_BIN}
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

echo "DuSheng agent uninstall marker found; cleaning local agent files."
cd /
systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
rm -f "${CONFIG_DIR}/agent.env"
rmdir "${CONFIG_DIR}" >/dev/null 2>&1 || true
rm -rf "${DATA_DIR}" "${LOG_DIR}" "${INSTALL_DIR}"
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
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
EnvironmentFile=-${CONFIG_DIR}/agent.env
ExecStart=${INSTALL_DIR}/dusheng-agent -base-url \${DUSHENG_API_URL} -install-token \${DUSHENG_INSTALL_TOKEN} -data-dir \${DUSHENG_DATA_DIR} -gost-path \${DUSHENG_GOST_PATH}
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
  write_service

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  if [ "${DUSHENG_NO_START:-0}" = "1" ]; then
    echo "Installed ${SERVICE_NAME}. Start it with: systemctl start ${SERVICE_NAME}"
  else
    systemctl restart "$SERVICE_NAME"
    echo "Installed and started ${SERVICE_NAME}."
  fi
}

main "$@"
