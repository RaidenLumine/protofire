#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_DIR="$ROOT_DIR/.agents/tasks"
STATE_FILE="$ROOT_DIR/.agents/state.yaml"

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

count_status() {
    local status="$1"
    local count=0
    local task
    shopt -s nullglob
    for task in "$TASK_DIR"/*.yaml; do
        [[ "$(basename "$task")" == "task-template.yaml" ]] && continue
        [[ "$(field "$task" status)" == "$status" ]] && ((count += 1))
    done
    shopt -u nullglob
    printf '%s' "$count"
}

if [[ ! -d "$TASK_DIR" ]]; then
    printf 'task directory not found: %s\n' "$TASK_DIR" >&2
    exit 1
fi

printf 'AI task status\n'
printf 'root: %s\n' "$ROOT_DIR"
[[ -f "$STATE_FILE" ]] && printf 'state: %s\n' "$STATE_FILE"
printf '\n'

printf 'counts: active=%s backlog=%s blocked=%s done=%s\n' \
    "$(count_status active)" \
    "$(count_status backlog)" \
    "$(count_status blocked)" \
    "$(count_status done)"
printf '\n'

printf 'tasks:\n'
shopt -s nullglob
for task in "$TASK_DIR"/*.yaml; do
    [[ "$(basename "$task")" == "task-template.yaml" ]] && continue
    id="$(field "$task" id)"
    status="$(field "$task" status)"
    priority="$(field "$task" priority)"
    title="$(field "$task" title)"
    printf '  %-8s %-7s %-48s %s\n' "$status" "$priority" "$id" "$title"
done
shopt -u nullglob
printf '\n'

active_count="$(count_status active)"
if [[ "$active_count" -eq 1 ]]; then
    active_task=""
    for task in "$TASK_DIR"/*.yaml; do
        [[ "$(basename "$task")" == "task-template.yaml" ]] && continue
        if [[ "$(field "$task" status)" == "active" ]]; then
            active_task="$task"
            break
        fi
    done
    printf 'active task: %s\n' "$(field "$active_task" id)"
    printf 'file: %s\n' "${active_task#$ROOT_DIR/}"
    printf '\n'
    printf 'standard prompt:\n'
    printf '按当前 .agents active task 连续推进，直到该 task 完成、验证失败、或遇到必须人工确认的边界；不要每做一小步就停。最后汇报已完成、验证结果、还有多少没弄。\n'
else
    printf 'active task problem: expected exactly 1 active task, found %s\n' "$active_count"
    exit 2
fi
