#!/usr/bin/env bash
set -euo pipefail

wait_http_ok() {
  local url="$1"; local timeout="${2:-60}"; local start=$(date +%s)
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    now=$(date +%s); if (( now - start > timeout )); then return 1; fi
    sleep 1
  done
}

echo '== Checking service health =='
wait_http_ok http://localhost:8080/healthz 120 || { echo 'orchestrator not healthy'; exit 1; }
wait_http_ok http://localhost:8090/healthz 120 || { echo 'reporter not healthy'; exit 1; }
wait_http_ok http://localhost:8070/healthz 120 || { echo 'ti-enrichment not healthy'; exit 1; }
echo 'Health OK'

echo '== Metrics endpoints =='
curl -fsS http://localhost:8080/metrics >/dev/null
curl -fsS http://localhost:8090/metrics >/dev/null
curl -fsS http://localhost:8070/metrics >/dev/null
echo 'Metrics OK'

echo '== Submitting analyze job =='
echo -n 'hello zorbox' > sample.bin
job_id=$(curl -fsS -F "file=@sample.bin" http://localhost:8080/analyze | jq -r .job_id)
test -n "$job_id" || { echo 'no job_id'; exit 1; }
echo "Job: $job_id"

echo '== Polling result =='
for i in {1..60}; do
  state=$(curl -fsS http://localhost:8080/result/$job_id | jq -r .state)
  if [[ "$state" == "done" || "$state" == "failed" ]]; then break; fi
  sleep 1
done
echo "Final state: $state"

echo '== Reporter direct test =='
curl -fsS -H 'Content-Type: application/json' -d '{"id":"t1","score":{"total":42,"rules":[]},"ti":{"domains":[],"ips":[]}}' http://localhost:8090/report | jq -e .pdf_url >/dev/null
echo '== Fetch exported PDF from reporter if available =='
pdf_url=$(curl -fsS http://localhost:8080/result/$job_id | jq -r .export.pdf_url)
if [[ "$pdf_url" != "null" && -n "$pdf_url" ]]; then
  curl -fsS -o /dev/null -w '%{http_code}\n' "http://localhost:8090$pdf_url" | grep -q '^200$'
fi
echo 'All checks passed.'
