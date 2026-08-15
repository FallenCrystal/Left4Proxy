#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -eu

# Enable pipefail if supported by the running shell
if (set -o pipefail 2>/dev/null); then
    set -o pipefail
fi

# ANSI color codes
COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_BLUE="\033[34m"
COLOR_YELLOW="\033[33m"
COLOR_CYAN="\033[36m"
COLOR_RED="\033[31m"

# Project root directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

OUTPUT_DIR="${SCRIPT_DIR}/bin"
mkdir -p "${OUTPUT_DIR}"

LDFLAGS="-s -w"

log_info() {
    printf "%b[INFO]%b %b\n" "${COLOR_CYAN}" "${COLOR_RESET}" "$1"
}

log_success() {
    printf "%b[SUCCESS]%b %b\n" "${COLOR_GREEN}" "${COLOR_RESET}" "$1"
}

log_warn() {
    printf "%b[WARN]%b %b\n" "${COLOR_YELLOW}" "${COLOR_RESET}" "$1"
}

log_error() {
    printf "%b[ERROR]%b %b\n" "${COLOR_RED}" "${COLOR_RESET}" "$1"
}

build_target() {
    target_name="$1"
    pkg_path="$2"
    goos="$3"
    goarch="$4"
    ext=""

    if [ "${goos}" = "windows" ]; then
        ext=".exe"
    fi

    out_file="${OUTPUT_DIR}/left4proxy-${target_name}-${goos}-${goarch}${ext}"

    log_info "Building ${COLOR_BOLD}${target_name}${COLOR_RESET} for ${COLOR_BLUE}${goos}/${goarch}${COLOR_RESET} -> ${out_file}..."

    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build -trimpath -ldflags="${LDFLAGS}" -o "${out_file}" "${pkg_path}"

    log_success "Built ${out_file} ($(du -h "${out_file}" | cut -f1))"
}

clean() {
    log_info "Cleaning ${OUTPUT_DIR}..."
    rm -rf "${OUTPUT_DIR:?}"/*
    log_success "Cleaned output directory."
}

build_all() {
    printf "%b=== Left4Proxy Build (amd64: Linux + Windows) ===%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
    build_target "server" "./cmd/server" "linux" "amd64"
    build_target "client" "./cmd/client" "linux" "amd64"
    build_target "server" "./cmd/server" "windows" "amd64"
    build_target "client" "./cmd/client" "windows" "amd64"
    printf "\n"
    log_success "All amd64 binaries have been built successfully in ${OUTPUT_DIR}/"
}

build_linux() {
    printf "%b=== Left4Proxy Build (Linux amd64) ===%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
    build_target "server" "./cmd/server" "linux" "amd64"
    build_target "client" "./cmd/client" "linux" "amd64"
}

build_windows() {
    printf "%b=== Left4Proxy Build (Windows amd64) ===%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
    build_target "server" "./cmd/server" "windows" "amd64"
    build_target "client" "./cmd/client" "windows" "amd64"
}

build_server() {
    printf "%b=== Left4Proxy Build (Server amd64) ===%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
    build_target "server" "./cmd/server" "linux" "amd64"
    build_target "server" "./cmd/server" "windows" "amd64"
}

build_client() {
    printf "%b=== Left4Proxy Build (Client amd64) ===%b\n" "${COLOR_BOLD}" "${COLOR_RESET}"
    build_target "client" "./cmd/client" "linux" "amd64"
    build_target "client" "./cmd/client" "windows" "amd64"
}

show_help() {
    printf "Usage: %s [command]\n\n" "$0"
    printf "Commands:\n"
    printf "  (empty) / all   Build both server and client for Linux & Windows (amd64)\n"
    printf "  linux           Build server and client for Linux (amd64)\n"
    printf "  windows         Build server and client for Windows (amd64)\n"
    printf "  server          Build server for Linux & Windows (amd64)\n"
    printf "  client          Build client for Linux & Windows (amd64)\n"
    printf "  clean           Remove all compiled binaries in bin/\n"
    printf "  help / -h       Show this help message\n"
}

case "${1:-all}" in
    all|"")
        build_all
        ;;
    linux)
        build_linux
        ;;
    windows)
        build_windows
        ;;
    server)
        build_server
        ;;
    client)
        build_client
        ;;
    clean)
        clean
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
