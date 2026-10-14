#!/bin/sh
# interpose CI-runner job-started hook - enforcement layer 3 (plan-agnostic).
#
# A GitHub self-hosted runner runs this before EVERY job (via
# ACTIONS_RUNNER_HOOK_JOB_STARTED) and FAILS the job if this exits non-zero. We use that
# to make the runner refuse any job that is NOT the sanctioned interpose ignition - so a
# repo cannot run an un-governed job on our runner, without needing a paid forge plan
# (GitHub org required-workflows need Team; this does not).
#
# It is root-owned and set via the runner's systemd Environment (not the runner-user's
# .env), so the non-root runner user can't disable it. The allowed ignition is the
# interpose workflow file; tighten later to a pinned reusable workflow so the step CONTENT
# is ours too (see docs/releases/release-integrations-plan.md section 10b, layer 3).

set -eu

POLICY="/etc/interpose/ci-policy.json"
# Default: the job's workflow must be our ignition file.
SUFFIX="/.github/workflows/interpose.yml"
if [ -f "$POLICY" ]; then
  v=$(grep -o '"require_workflow_suffix"[[:space:]]*:[[:space:]]*"[^"]*"' "$POLICY" 2>/dev/null \
        | sed 's/.*"\([^"]*\)"[[:space:]]*$/\1/')
  [ -n "${v:-}" ] && SUFFIX="$v"
fi

# GITHUB_WORKFLOW_REF e.g. interposed/xyz/.github/workflows/interpose.yml@refs/heads/main
REF="${GITHUB_WORKFLOW_REF:-}"
REF="${REF%@*}"   # strip the @git-ref

case "$REF" in
  *"$SUFFIX")
    echo "interpose: job allowed - governed by $REF"
    exit 0
    ;;
  *)
    echo "interpose: REFUSED." >&2
    echo "interpose: this CI runner only runs interpose-governed pipelines ($SUFFIX)." >&2
    echo "interpose: job workflow was '${REF:-<unknown>}'." >&2
    exit 1
    ;;
esac
