#!/usr/bin/env bash
# Dual-registry OCI build & push helper for Architecture A (ludus-server + lux).
# Supports rootless Podman or Docker Buildx and pushes to:
#   1. Sophon Nexus hosted registry: registry-push.<SOPHON_DOMAIN>/ludus/{ludus-server,lux}:<TAG>
#      (pulled on infravm via registry.<SOPHON_DOMAIN>/ludus/{ludus-server,lux}:<TAG>)
#   2. GitHub Container Registry:    ghcr.io/cseelhoff/{ludus-server,ludus-ux}:<TAG>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUDUS_REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LUX_REPO_DIR="${LUX_REPO_DIR:-$(cd "${LUDUS_REPO_DIR}/.." && pwd)/ludus-ux}"

CONTAINER_ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "${CONTAINER_ENGINE}" ]]; then
  if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="podman"
  elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
  else
    echo "ERROR: neither podman nor docker found in PATH" >&2
    exit 1
  fi
fi

VERSION_STRING="${VERSION_STRING:-2.0.0-container}"
GIT_SHA="$(git -C "${LUDUS_REPO_DIR}" rev-parse --short HEAD 2>/dev/null || echo local)"
IMAGE_TAG="${IMAGE_TAG:-${VERSION_STRING}-${GIT_SHA}}"
PUSH_LATEST="${PUSH_LATEST:-true}"

SOPHON_PUSH_REGISTRY="${SOPHON_PUSH_REGISTRY:-}"
if [[ -z "${SOPHON_PUSH_REGISTRY}" && -n "${SOPHON_DOMAIN:-}" ]]; then
  SOPHON_PUSH_REGISTRY="registry-push.${SOPHON_DOMAIN}/ludus"
fi
GHCR_NAMESPACE="${GHCR_NAMESPACE:-ghcr.io/cseelhoff}"

BUILD_ONLY=false
PUSH_SOPHON=true
PUSH_GHCR=true
SKIP_LUDUS=false
SKIP_LUX=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --build-only               Build local OCI images only (do not push)
  --tag <tag>                Primary image tag (default: ${IMAGE_TAG})
  --sophon-domain <domain>   Sophon domain -> pushes to registry-push.<domain>/ludus/*
  --sophon-registry <prefix> Explicit Nexus push prefix (e.g. registry-push.example.com/ludus)
  --ghcr-namespace <ns>      GHCR namespace (default: ${GHCR_NAMESPACE})
  --no-sophon                Skip Sophon Nexus push
  --no-ghcr                  Skip GHCR push
  --no-latest                Do not tag/push :latest alongside --tag
  --ludus-only               Build/push ludus-server only
  --lux-only                 Build/push lux only
  --lux-dir <path>           Path to ludus-ux repo (default: ${LUX_REPO_DIR})
  -h, --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only) BUILD_ONLY=true; shift ;;
    --tag) IMAGE_TAG="$2"; shift 2 ;;
    --sophon-domain) SOPHON_PUSH_REGISTRY="registry-push.$2/ludus"; shift 2 ;;
    --sophon-registry) SOPHON_PUSH_REGISTRY="${2%/}"; shift 2 ;;
    --ghcr-namespace) GHCR_NAMESPACE="${2%/}"; shift 2 ;;
    --no-sophon) PUSH_SOPHON=false; shift ;;
    --no-ghcr) PUSH_GHCR=false; shift ;;
    --no-latest) PUSH_LATEST=false; shift ;;
    --ludus-only) SKIP_LUX=true; shift ;;
    --lux-only) SKIP_LUDUS=true; shift ;;
    --lux-dir) LUX_REPO_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

echo "==> Using container engine: ${CONTAINER_ENGINE}"
echo "==> Primary tag:            ${IMAGE_TAG}"

FORMAT_ARGS=()
if [[ "${CONTAINER_ENGINE}" == "podman" ]]; then
  # Docker v2s2 manifest format preserves HEALTHCHECK metadata in Podman builds
  FORMAT_ARGS=(--format docker)
fi

if [[ "${SKIP_LUDUS}" == "false" ]]; then
  echo "==> Building ludus-server (${LUDUS_REPO_DIR})..."
  "${CONTAINER_ENGINE}" build \
    "${FORMAT_ARGS[@]}" \
    --build-arg VERSION_STRING="${VERSION_STRING}" \
    --build-arg GIT_COMMIT="${GIT_SHA}" \
    -f "${LUDUS_REPO_DIR}/docker/Containerfile.ludus" \
    -t "localhost/ludus-server:${IMAGE_TAG}" \
    -t "localhost/ludus-server:local" \
    "${LUDUS_REPO_DIR}"
fi

if [[ "${SKIP_LUX}" == "false" ]]; then
  if [[ ! -d "${LUX_REPO_DIR}" ]]; then
    echo "ERROR: LUX repo not found at ${LUX_REPO_DIR} (override with --lux-dir or --ludus-only)" >&2
    exit 1
  fi
  echo "==> Building lux (${LUX_REPO_DIR})..."
  "${CONTAINER_ENGINE}" build \
    "${FORMAT_ARGS[@]}" \
    -f "${LUX_REPO_DIR}/docker/Dockerfile" \
    -t "localhost/lux:${IMAGE_TAG}" \
    -t "localhost/lux:local" \
    "${LUX_REPO_DIR}"
fi

if [[ "${BUILD_ONLY}" == "true" ]]; then
  echo "==> --build-only requested; local images ready:"
  [[ "${SKIP_LUDUS}" == "false" ]] && echo "    localhost/ludus-server:${IMAGE_TAG}"
  [[ "${SKIP_LUX}" == "false" ]]   && echo "    localhost/lux:${IMAGE_TAG}"
  exit 0
fi

tag_and_push() {
  local src_img="$1"
  local dst_repo="$2"

  echo "==> Pushing ${dst_repo}:${IMAGE_TAG}"
  "${CONTAINER_ENGINE}" tag "${src_img}" "${dst_repo}:${IMAGE_TAG}"
  "${CONTAINER_ENGINE}" push "${dst_repo}:${IMAGE_TAG}"

  if [[ "${PUSH_LATEST}" == "true" ]]; then
    echo "==> Pushing ${dst_repo}:latest"
    "${CONTAINER_ENGINE}" tag "${src_img}" "${dst_repo}:latest"
    "${CONTAINER_ENGINE}" push "${dst_repo}:latest"
  fi
}

if [[ "${PUSH_SOPHON}" == "true" ]]; then
  if [[ -z "${SOPHON_PUSH_REGISTRY}" ]]; then
    echo "WARN: SOPHON_DOMAIN / --sophon-registry not set; skipping Sophon Nexus push." >&2
  else
    [[ "${SKIP_LUDUS}" == "false" ]] && tag_and_push "localhost/ludus-server:${IMAGE_TAG}" "${SOPHON_PUSH_REGISTRY}/ludus-server"
    [[ "${SKIP_LUX}" == "false" ]]   && tag_and_push "localhost/lux:${IMAGE_TAG}" "${SOPHON_PUSH_REGISTRY}/lux"
  fi
fi

if [[ "${PUSH_GHCR}" == "true" && -n "${GHCR_NAMESPACE}" ]]; then
  [[ "${SKIP_LUDUS}" == "false" ]] && tag_and_push "localhost/ludus-server:${IMAGE_TAG}" "${GHCR_NAMESPACE}/ludus-server"
  [[ "${SKIP_LUX}" == "false" ]]   && tag_and_push "localhost/lux:${IMAGE_TAG}" "${GHCR_NAMESPACE}/ludus-ux"
fi

echo "==> Done."
