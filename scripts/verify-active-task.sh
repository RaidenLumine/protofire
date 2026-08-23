#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_DIR="$ROOT_DIR/.agents/tasks"
RUN=0

usage() {
    cat <<'USAGE'
Usage: scripts/verify-active-task.sh [--run]

Without --run, print the verification commands listed by the single active task.
With --run, execute them sequentially from the repository root.

Set AGENT_CARGO_TARGET_DIR=target/codex-host to isolate host cargo artifacts when
the default target directory has been used for mixed host/bare-metal checks.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run)
            RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

field() {
    local file="$1"
    local key="$2"
    awk -v key="$key" '
        $1 == key ":" {
            sub(/^[^:]*:[[:space:]]*/, "")
            print
            exit
        }
    ' "$file"
}

active_tasks=()
shopt -s nullglob
for task in "$TASK_DIR"/*.yaml; do
    [[ "$(basename "$task")" == "task-template.yaml" ]] && continue
    if [[ "$(field "$task" status)" == "active" ]]; then
        active_tasks+=("$task")
    fi
done
shopt -u nullglob

if [[ "${#active_tasks[@]}" -ne 1 ]]; then
    printf 'expected exactly 1 active task, found %s\n' "${#active_tasks[@]}" >&2
    exit 2
fi

active_task="${active_tasks[0]}"
mapfile -t commands < <(
    awk '
        /^verification:/ {
            in_verification = 1
            next
        }
        in_verification && /^[^[:space:]][^:]*:/ {
            exit
        }
        in_verification && /^  - / {
            sub(/^  - /, "")
            print
        }
    ' "$active_task"
)

if [[ "${#commands[@]}" -eq 0 ]]; then
    printf 'active task has no verification commands: %s\n' "${active_task#$ROOT_DIR/}" >&2
    exit 2
fi

printf 'active task: %s\n' "$(field "$active_task" id)"
printf 'file: %s\n' "${active_task#$ROOT_DIR/}"
printf '\n'

if [[ "$RUN" -eq 0 ]]; then
    printf 'verification commands:\n'
    for command in "${commands[@]}"; do
        printf '  %s\n' "$command"
    done
    printf '\n'
    printf 'run with: scripts/verify-active-task.sh --run\n'
    exit 0
fi

cd "$ROOT_DIR"
for command in "${commands[@]}"; do
    printf '\n==> %s\n' "$command"
    case "$command" in
        cargo*)
            if [[ -n "${AGENT_CARGO_TARGET_DIR:-}" ]]; then
                CARGO_TARGET_DIR="$AGENT_CARGO_TARGET_DIR" bash -lc "$command"
            else
                bash -lc "$command"
            fi
            ;;
        *)
            bash -lc "$command"
            ;;
    esac
done
