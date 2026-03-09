#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Release rollback automation
#
# Usage:
#   ./scripts/rollback.sh <component> [version_tag]
#
# Components:
#   control-plane  — Roll back the API server
#   gateway        — Roll back nftables/tc templates
#   client         — Signal client config rollback
#   all            — Roll back everything
#
# Examples:
#   ./scripts/rollback.sh control-plane v1.2.0
#   ./scripts/rollback.sh all
# ──────────────────────────────────────────────────────────────

COMPONENT="${1:-}"
VERSION="${2:-}"

if [[ -z "$COMPONENT" ]]; then
  echo "Usage: $0 <component> [version_tag]"
  echo "Components: control-plane | gateway | client | all"
  exit 1
fi

log() { echo "[rollback] $(date -u +%FT%TZ) $*"; }

rollback_control_plane() {
  log "Rolling back control-plane..."

  if [[ -n "$VERSION" ]]; then
    log "Checking out version: $VERSION"
    git checkout "$VERSION" -- backend/
  else
    log "Reverting to previous commit"
    git checkout HEAD~1 -- backend/
  fi

  if command -v docker &>/dev/null && docker ps --filter "name=control-plane" --format '{{.Names}}' | grep -q control-plane; then
    log "Restarting Docker container..."
    docker compose restart control-plane
  elif command -v systemctl &>/dev/null && systemctl is-active --quiet vpn-control-plane; then
    log "Restarting systemd service..."
    systemctl restart vpn-control-plane
  else
    log "No managed service found. Manual restart required."
  fi

  log "Control-plane rolled back."
}

rollback_gateway() {
  log "Rolling back gateway policies..."

  if [[ -n "$VERSION" ]]; then
    git checkout "$VERSION" -- gateway/
  else
    git checkout HEAD~1 -- gateway/
  fi

  if command -v nft &>/dev/null; then
    log "Reapplying previous nftables rules..."
    bash gateway/scripts/apply_egress_policy.sh 2>/dev/null || log "WARNING: nftables apply failed"
  fi

  log "Gateway rolled back."
}

rollback_client() {
  log "Signaling client config rollback..."
  log "NOTE: Client rollback requires pushing previous config via control-plane API."
  log "No automatic rollback — flag for manual action."
}

case "$COMPONENT" in
  control-plane) rollback_control_plane ;;
  gateway)       rollback_gateway ;;
  client)        rollback_client ;;
  all)
    rollback_control_plane
    rollback_gateway
    rollback_client
    ;;
  *)
    echo "Unknown component: $COMPONENT"
    exit 1
    ;;
esac

log "Rollback complete for: $COMPONENT"
log "ACTION REQUIRED: Monitor core metrics for 30 minutes."
log "  - 建连成功率"
log "  - 节点异常率"
log "  - 风控误杀率"
