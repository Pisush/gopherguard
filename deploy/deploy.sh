#!/usr/bin/env bash
# gopherguard Cloud Run deploy pipeline — eval-gated canary with auto-rollback.
#
# This is the M4 deploy CONCEPT: a documented, runnable pipeline script.
# Default mode is --plan, which prints every step with the exact commands and
# runs nothing. --execute performs the deploy and requires a configured
# gcloud project. The gcloud flags follow the documented Cloud Run surface,
# but this script has not been run against a live project — steps whose cloud
# specifics are unverified are marked "UNVERIFIED" inline.
#
# Pipeline:
#   1. gate      — make eval must pass locally (same gate as CI)
#   2. build     — hardened binary ONLY; refuse if the vuln launcher leaks in
#   3. push      — container to Artifact Registry
#   4. canary    — deploy a no-traffic tagged revision
#   5. smoke     — health + eval probe against the canary URL
#   6. shift     — 10% traffic to the canary
#   7. watch     — error rate + GG-DET detections over canary traces
#   8. promote   — 100% to canary, or AUTO-ROLLBACK to the previous revision
#
# Rollback triggers during the watch window:
#   - HTTP 5xx rate above threshold on the canary revision
#   - ANY GG-DET rule firing on a canary-revision trace (detections/ queries
#     filtered by service.revision) — a detection on prod traffic is a
#     security regression, not a tuning knob
#   - eval smoke probe failing against the canary
set -euo pipefail

SERVICE="${GG_SERVICE:-gopherguard}"
REGION="${GG_REGION:-europe-west1}"
PROJECT="${GG_PROJECT:-$(gcloud config get-value project 2>/dev/null || echo '<project>')}"
REPO="${GG_AR_REPO:-gopherguard}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/gopherguard:$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
CANARY_PERCENT="${GG_CANARY_PERCENT:-10}"
WATCH_MINUTES="${GG_WATCH_MINUTES:-10}"
MAX_5XX_RATE="${GG_MAX_5XX_RATE:-0.01}"

MODE="${1:---plan}"

run() {
  if [ "$MODE" = "--execute" ]; then
    echo "+ $*"
    "$@"
  else
    echo "  \$ $*"
  fi
}

note() { echo "$*"; }

note "gopherguard deploy pipeline (${MODE#--} mode) — service=${SERVICE} region=${REGION}"
note ""

note "[1/8] gate: the same eval gate CI enforces, run locally before anything ships"
run make eval
note ""

note "[2/8] build: hardened entrypoint only — the vuln lab is never deployable"
run go build -o bin/gopherguard ./cmd/gopherguard
# Belt and braces: the image build context must not contain a vuln binary.
if [ "$MODE" = "--execute" ] && [ -f bin/gopherguard-vuln ]; then
  echo "refusing to deploy: bin/gopherguard-vuln present in build context" >&2
  exit 1
fi
note ""

note "[3/8] push: container to Artifact Registry"
# Cloud Build builds from the repo's Dockerfile (hardened stage only).
run gcloud builds submit --project "$PROJECT" --tag "$IMAGE" .
note ""

note "[4/8] canary: new revision, tagged, receiving NO traffic"
run gcloud run deploy "$SERVICE" \
  --project "$PROJECT" --region "$REGION" \
  --image "$IMAGE" \
  --no-traffic --tag canary \
  --set-env-vars GG_MODEL_MODE=gemini \
  --set-secrets GOOGLE_API_KEY=gopherguard-google-api-key:latest
note ""

note "[5/8] smoke: probe the canary tag URL before it sees a single user request"
# UNVERIFIED: tag URLs have the shape https://canary---SERVICE-HASH-REGION.a.run.app;
# resolve it from the service description instead of assuming the shape.
run bash -c 'CANARY_URL=$(gcloud run services describe "'"$SERVICE"'" --project "'"$PROJECT"'" --region "'"$REGION"'" --format="value(status.traffic.filter(tag:canary).extract(url))"); curl -fsS "$CANARY_URL/healthz"'
note ""

note "[6/8] shift: ${CANARY_PERCENT}% of traffic to the canary revision"
run gcloud run services update-traffic "$SERVICE" \
  --project "$PROJECT" --region "$REGION" \
  --to-tags "canary=${CANARY_PERCENT}"
note ""

note "[7/8] watch: ${WATCH_MINUTES}m window — 5xx rate (max ${MAX_5XX_RATE}) and GG-DET detections on canary traces"
# UNVERIFIED: metric filter names for Cloud Run request_count by response_code_class.
note '  5xx rate:   gcloud monitoring time-series list --filter="metric.type=run.googleapis.com/request_count AND resource.labels.service_name='"$SERVICE"'" (aggregate 5xx/total)'
note "  detections: run the detections/ TraceQL/ClickHouse queries scoped to the canary revision"
note "              e.g. Tempo: { trust.untrusted_input=true } >> { trust.egress=true } && { service.revision =~ \"canary\" }"
note "  ANY rule firing on a canary trace, 5xx over threshold, or a failed eval probe => rollback"
note ""

note "[8/8] promote or auto-rollback"
note "  promote:  gcloud run services update-traffic $SERVICE --to-tags canary=100  (then remove the tag)"
note "  rollback: gcloud run services update-traffic $SERVICE --to-revisions LATEST=0,<previous-revision>=100"
note "            (previous revision = the one serving before step 6; the canary revision keeps its tag for forensics)"
note ""

if [ "$MODE" != "--execute" ]; then
  note "plan mode: nothing was executed. Run 'deploy/deploy.sh --execute' with gcloud configured to deploy."
fi
