#!/usr/bin/env bash
# claude-kind files (.claude/, CLAUDE.md) never share a commit with another kind
# (.claude/rules/commit-messages.md: type them `claude:`, stage by explicit path).
# Deliberate exception: SKIP=staged-kind git commit ...
set -euo pipefail
staged=$(git -c core.quotePath=false diff --cached --name-only)
[ -z "$staged" ] && exit 0
claude=$(grep -cE '^(\.claude/|CLAUDE\.md$)' <<<"$staged" || true)
other=$(grep -cvE '^(\.claude/|CLAUDE\.md$)' <<<"$staged" || true)
if [ "$claude" -gt 0 ] && [ "$other" -gt 0 ]; then
    printf 'claude-kind files mixed with another kind — split the commit (one kind per commit):\n'
    sed 's/^/  /' <<<"$staged"
    exit 1
fi
