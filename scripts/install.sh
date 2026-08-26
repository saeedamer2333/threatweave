#!/usr/bin/env bash
#
# ThreatWeave installer.
#
#   curl -fsSL https://raw.githubusercontent.com/saeedamer2333/threatweave/main/scripts/install.sh | bash
#
# Checks prerequisites, fetches the project, writes a .env with the host path
# the pipeline needs, and starts the stack. Nothing is installed on the host
# except Docker itself (and only if the user agrees).

set -euo pipefail

REPO_URL="${THREATWEAVE_REPO:-https://github.com/saeedamer2333/threatweave.git}"
INSTALL_DIR="${THREATWEAVE_DIR:-$HOME/threatweave}"
BRANCH="${THREATWEAVE_BRANCH:-main}"

# ----------------------------------------------------------------- output --
BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'

info()  { printf '%s==>%s %s\n' "$BLUE$BOLD" "$RESET" "$1"; }
ok()    { printf '%s  ok%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '%s  !!%s %s\n' "$YELLOW" "$RESET" "$1"; }
die()   { printf '%s error:%s %s\n' "$RED$BOLD" "$RESET" "$1" >&2; exit 1; }

# ----------------------------------------------------------- prerequisites --
need_cmd() { command -v "$1" >/dev/null 2>&1; }

install_docker() {
    warn "Docker is not installed."
    if [ ! -t 0 ]; then
        # Piped from curl: stdin is the script, so we cannot prompt safely.
        die "Install Docker first (https://docs.docker.com/engine/install/), then re-run."
    fi
    read -r -p "  Install Docker via get.docker.com? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || die "Docker is required."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER" || true
    ok "Docker installed. You may need to log out and back in for group changes."
}

check_prereqs() {
    info "Checking prerequisites"

    need_cmd git || die "git is required."
    ok "git $(git --version | awk '{print $3}')"

    need_cmd docker || install_docker
    docker info >/dev/null 2>&1 || die "Docker is installed but the daemon is not running. Start Docker and re-run."
    ok "docker $(docker --version | awk '{print $3}' | tr -d ,)"

    docker compose version >/dev/null 2>&1 \
        || die "Docker Compose v2 is required (comes with modern Docker)."
    ok "compose $(docker compose version --short)"

    # Memory: SonarQube alone wants ~3GB, so warn rather than fail.
    if need_cmd free; then
        local mb; mb=$(free -m | awk '/^Mem:/{print $2}')
        if [ "$mb" -lt 6000 ]; then
            warn "Only ${mb}MB RAM detected. The core stack needs ~4GB;"
            warn "the optional SonarQube profile needs ~3GB more."
        else
            ok "${mb}MB RAM available"
        fi
    fi

    if need_cmd aws; then
        if aws sts get-caller-identity >/dev/null 2>&1; then
            ok "AWS credentials detected ($(aws sts get-caller-identity --query Account --output text))"
        else
            warn "AWS CLI found but no working credentials. Cloud checks will be skipped."
            warn "Run 'aws configure' later - the dashboard picks it up automatically."
        fi
    else
        warn "AWS CLI not found. Cloud checks will be skipped until you run 'aws configure'."
    fi
}

# ------------------------------------------------------------------ fetch --
fetch_project() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Updating existing install at $INSTALL_DIR"
        git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
    else
        info "Cloning into $INSTALL_DIR"
        [ -e "$INSTALL_DIR" ] && die "$INSTALL_DIR exists and is not a git checkout."
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    fi
    ok "Project ready"
}

# --------------------------------------------------------------- configure --
configure() {
    info "Writing configuration"
    cd "$INSTALL_DIR/implementation"

    # HOST_WORKSPACE must be the host-side absolute path: the pipeline runs
    # scanners as sibling containers, whose volume mounts are resolved by the
    # host daemon rather than inside the Jenkins container.
    local host_path; host_path="$(pwd)"

    if [ -f .env ]; then
        ok ".env already exists, leaving it untouched"
        return
    fi

    # The project to scan. It is mounted at /target, so it can live anywhere
    # on the host rather than having to be copied inside the install
    # directory. THREATWEAVE_TARGET allows a non-interactive install to set
    # it; otherwise the default is the bundled demo target.
    local target_path="${THREATWEAVE_TARGET:-./demo-app}"

    if [ -z "${THREATWEAVE_TARGET:-}" ] && [ -t 0 ]; then
        # Not available when piped from curl: stdin is the script itself.
        printf '\n  Which project should ThreatWeave scan?\n'
        printf '  %sAbsolute path on this machine, or blank for the demo target.%s\n' "$DIM" "$RESET"
        read -r -p "  Path [demo target]: " reply
        if [ -n "$reply" ]; then
            if [ -d "$reply" ]; then
                target_path="$(cd "$reply" && pwd)"
            else
                warn "$reply is not a directory - using the demo target instead."
            fi
        fi
    fi

    sed -e "s|^HOST_WORKSPACE=.*|HOST_WORKSPACE=${host_path}|" \
        -e "s|^TARGET_PATH=.*|TARGET_PATH=${target_path}|" \
        .env.example > .env
    ok "Wrote .env (HOST_WORKSPACE=${host_path})"

    if [ "$target_path" = "./demo-app" ]; then
        "$INSTALL_DIR/implementation/scripts/fetch-demo-target.sh"
        ok "Scan target: bundled demo (OWASP Juice Shop)"
    else
        ok "Scan target: ${target_path}  (mounted at /target)"
        warn "Set SOURCE_DIR=/target when you run the pipeline."
    fi
}

# ------------------------------------------------------------------- start --
start_stack() {
    info "Building and starting the stack (first run pulls several images)"
    docker compose up -d --build

    info "Waiting for services"
    local waited=0
    until curl -sf http://localhost:4000/api/settings >/dev/null 2>&1; do
        sleep 5; waited=$((waited + 5))
        [ "$waited" -ge 300 ] && { warn "API did not respond within 5 minutes."; break; }
    done
    [ "$waited" -lt 300 ] && ok "API is up"

    waited=0
    until curl -sf http://localhost:8080/login >/dev/null 2>&1; do
        sleep 5; waited=$((waited + 5))
        [ "$waited" -ge 300 ] && { warn "Jenkins did not respond within 5 minutes."; break; }
    done
    [ "$waited" -lt 300 ] && ok "Jenkins is up"
}

summary() {
    cat <<EOF

${GREEN}${BOLD}ThreatWeave is running.${RESET}

  Dashboard   ${BOLD}http://localhost:3000${RESET}
  Jenkins     ${BOLD}http://localhost:8080${RESET}   ${DIM}(admin / admin)${RESET}
  API         ${BOLD}http://localhost:4000/api${RESET}

${BOLD}Next steps${RESET}
  1. Open the dashboard and check Settings for your AWS connection status.
     ${DIM}Credentials come from ~/.aws - run 'aws configure' if none are detected.
     Only read-only access is needed: attach the SecurityAudit policy.${RESET}
  2. Trigger a scan from the dashboard, or run the Jenkins job
     ${DIM}threatweave-pipeline${RESET} for the full DevSecOps pipeline.

${BOLD}Optional profiles${RESET}
  docker compose --profile sast up -d     ${DIM}SonarQube for SAST (needs ~3GB RAM)${RESET}
  docker compose --profile demo up -d     ${DIM}OWASP Juice Shop as a scan target${RESET}

${BOLD}Manage${RESET}
  docker compose logs -f       docker compose down       docker compose down -v

EOF
}

main() {
    printf '\n%sThreatWeave%s - AIOps security alert prioritisation\n\n' "$BOLD" "$RESET"
    check_prereqs
    fetch_project
    configure
    start_stack
    summary
}

main "$@"
