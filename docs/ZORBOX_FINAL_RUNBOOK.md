# ZORBOX: Milli Sandbox Layihəsi — Final Runbook (MVP)

Bu sənəd 48 saatlıq hackathon üçün hazırlanmış ZORBOX sisteminin başdan‑sona istifadəsini, arxitekturasını, qurulumunu, testini, monitorinqini və təhlükəsizlik xüsusiyyətlərini bir yerdə izah edir. Hədəf: heç öz sistemi tanımayan texniki istifadəçi belə aşağıdakı addımlarla sistemi qura bilsin, işlədə bilsin və yoxlayıb nəticələri təqdim etsin.

---

## 1) Sistem Təsviri və Data Flow

- Upload/URL → Orchestrator job yaradır → (Static Analyzer + Sandbox Native + OSS Sandbox adapterləri) → TI Enrichment → Reporter (JSON/PDF/STIX) → UI göstərir.
- Orchestrator mərkəzi “state tracker”dir: queued → running → enriching → reporting → done/failed.
- Monitorinq: hər modulda Prometheus metrics; Docker Compose ilə Prometheus/Grafana; basic alertlər.

Data Flow (qısa)
1. UI `POST /analyze` (file və ya URL) çağırır; `job_id` alır.
2. Orchestrator faylı qəbul edir (və ya URL-dən endirir), karantinə yazır, hash/mime yoxlayır; arxivdirsə parol istəyə bilər.
3. Static Analyzer və (mövcuddursa) Sandbox Native/adapterlərdən nəticələr toplanır.
4. TI Enrichment (lokal + opsional VT) reputasiya verir.
5. Reporter JSON/PDF/STIX export yaradır; Orchestrator `GET /result/{id}` ilə export linkləri verir.
6. UI nəticələri göstərir, feedback (FP) və reanalysis göndərə bilir.

---

## 2) Komponentlər və Rollar

Monorepo modulları:
- `orchestrator/` — FastAPI; API (`/analyze`, `/result`, `/jobs`, `/provide-password`, `/metrics`, `/audit`), storage və state, audit, arxiv/pasword axını.
- `static-analyzer/` — FastAPI; `POST /analyze` statik analiz (PE/Office/JS/ps1/vbs/bat/py/elf); `GET /schema`, `GET /metrics`.
- `ti-enrichment/` — FastAPI; `POST /enrich` (lokal DB + opsional VirusTotal); `GET /metrics`.
- `reporter-service/` — FastAPI; `POST /report` → JSON/PDF/STIX; `GET /schema`, `GET /example`, `GET /exports/...`, `GET /metrics`.
- `sandbox-native/` — FastAPI; `POST /run` adapter=`strace|firejail|bwrap|nsjail|mock`; `GET /metrics`.
- `frontend-ui/` — React+Vite; Upload/URL/password, Job status, Export linkləri, YARA/IOC/TIMELINE paneli, Feedback/Reanalysis, Audit.
- `infra/` — Docker Compose, Prometheus/Grafana, smoke skriptləri; `infra/k8s/` namespace+deploy+svc+networkpolicy YAML-ları.
- `.github/workflows/` — CI-lər: Python, Node, Compose E2E build və s.

---

## 3) Qurulum və İşə Salma

### 3.1 Docker Compose (lokal)

Tələblər: Docker + Docker Compose, 3.11 Python təsiri konteynerdədir.

Komanda:
```bash
cd infra
docker compose up -d --build
```

Yoxlama (health):
```bash
./smoke.sh         # Linux/macOS
# və ya
PowerShell -File .\smoke.ps1   # Windows
```

Modulların portları:
- Orchestrator: http://localhost:8080
- Reporter: http://localhost:8090
- TI-Enrichment: http://localhost:8070
- Static Analyzer: http://localhost:8060
- Sandbox Native: http://localhost:8050
- Prometheus: http://localhost:9090 (compose stack)
- Grafana: http://localhost:3000 (compose stack, admin/admin)

### 3.2 Kubernetes (opsional demo manifestləri)

```bash
kubectl apply -f infra/k8s/namespace.yaml
kubectl apply -f infra/k8s/static-analyzer.yaml
kubectl apply -f infra/k8s/reporter.yaml
kubectl apply -f infra/k8s/ti.yaml     # Secret vt-api/api_key boş gəlir, ehtiyac varsa doldurun
kubectl apply -f infra/k8s/sandbox.yaml
kubectl apply -f infra/k8s/orchestrator.yaml
```

Qeyd: K8s manifestləri MVP üçündür (NodePort/Ingress əlavə edin əgər external access lazımdır). Orchestrator üçün egress NetworkPolicy yalnız daxili servislərə icazə verir.

---

## 4) Modul‑Modul İstifadə və API

### 4.1 Orchestrator (8080)

Əsas Endpointlər:
- `POST /analyze` — Multipart `file` və ya `url`; optional `password`; optional `adapters` (virgüllə: `strace,firejail`). Cavab: `{ job_id, accepted }`.
- `GET /result/{id}` — Job snapshot (state, timestamps, file meta, export linkləri, error).
- `GET /jobs?state=queued|running|...` — Job siyahısı.
- `POST /provide-password` — `{ job_id, password }` şifrəli arxivlər üçün.
- `GET /metrics` — Prometheus metrics.
- `GET /healthz` — Liveness.
- `POST /frontend-errors`, `POST /frontend-rum` — UI telemetry (counter artırır).
- `POST /feedback` — `{ job_id, kind, comment }`.
- `POST /reanalysis` — `{ job_id }` → yeni job yaradır (MVP simulyasiya).
- `GET /audit?limit=100` — Son audit hadisələri (JSONL həm də `uploads/audit.log`‑a yazılır).

Mühit dəyişənləri (env):
- `REPORTER_BASE` (default `http://reporter:8090` compose daxilində / `http://localhost:8090` lokal)
- `ANALYZER_BASE` (default `http://static_analyzer:8060` compose daxilində)
- `TI_BASE`, `SANDBOX_BASE` — TI və Sandbox URL.
- `CUCKOO_BASE`, `CAPE_BASE` — varsa OSS sandbox API-ləri.
- `URL_ALLOWLIST`, `URL_BLOCKLIST` — host pattern (`,` ilə ayırın; `*` dəstəklənir).
- `UPLOADS_QUOTA_MB` — kvota (0=disabled), `RETENTION_HOURS` — retention (0=disabled).
- `UI_ORIGIN` — CORS üçün (default `http://localhost:5173`).

Arxiv/parol axını:
- ZIP: şifrəli aşkarlanır; parol yoxdursa state=`waiting_password`; parol təqdim ediləndə `list`/məhdud `extract`.
- 7z: py7zr ilə `list`; parol tələbini aşkar edir.
- RAR: aşkar edilir; parol təqdim edilərsə `rarfile` varsa `list`; backend yoxdursa 501 cavab (MVP qeydi).
- ISO/IMG: heuristik aşkar (extract yoxdur, yalnız meta flag).

Təhlükəsizlik / Storage:
- Fayllar `app/uploads/<job-id>/` altında; dirs `0700`, fayllar `0600`.
- Safe path (zip‑slip qorunması), atomic meta yazma, kvota və retention.
- Konteynerlər non‑root `svc` istifadəçisi ilə (Dockerfile dəyişiklikləri).

Metrics (seçmə):
- `orchestrator_jobs_in_state{state}` (gauge), `orchestrator_queue_length` (gauge), `orchestrator_job_latency_seconds` (histogram)
- `frontend_errors_total`, `frontend_rum_events_total`

CLI test nümunələri:
```bash
# Fayl upload
curl -F "file=@sample.bin" http://localhost:8080/analyze
# URL analizi
curl -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'url=https://example.com/sample.bin' http://localhost:8080/analyze
# Nəticə
curl http://localhost:8080/result/<job_id>
# Şifrə təqdim et (waiting_password)
curl -H 'Content-Type: application/json' -d '{"job_id":"<job_id>","password":"infected"}' \
  http://localhost:8080/provide-password
# Audit
curl http://localhost:8080/audit?limit=50
```

### 4.2 Static Analyzer (8060)

Endpointlər:
- `POST /analyze` — faylı oxuyur, hash/heuristics/pe/office/js/ps1/vbs/bat/py/elf və `yara_hits` qaytarır.
- `GET /schema` — analyzer çıxış JSON Schema.
- `GET /metrics`, `GET /healthz`.

Heuristics (seçmə):
- PE: arch, compile_ts, sections (entropy, RWX), suspicious_imports, packer_flags, exports_count.
- Office: oletools ilə VBA aşkar + IOC (URL) çıxarışı.
- JS/PS1/VBS/BAT/PY/ELF: eval/unescape, EncodedCommand, mshta/certutil/powershell/subprocess və s.
- YARA: `app/rules/*.yar` varsa tətbiq olunur.

### 4.3 TI Enrichment (8070)

Endpointlər:
- `POST /enrich` — `{ domains:[], ips:[], hashes:[] }` → `{ reputation: { domains|ips|hashes -> good/unknown/bad }, vt: bool }`.
- `GET /metrics`, `GET /healthz`.

Env:
- `VT_API_KEY` — varsa ilk 3 hash üçün VT v3 look‑up, `malicious/suspicious>0` olduqda `bad` etiketi.

### 4.4 Reporter (8090)

Endpointlər:
- `POST /report` — Aggregated JSON → yazır: `report.json`, `report.pdf`, `report.stix.json`; cavab URL-lər verir.
- `GET /exports/<job-id>/...` — yüklənə bilən export faylları.
- `GET /schema` — report schema.
- `GET /example` — demo export linkləri üçün nümunə.
- `GET /metrics`, `GET /healthz`.

Scoring:
- Rule‑based (YARA, heuristics, macros, PE packer/suspicious_imports/RWX, TI bad və s.).
- AI‑minimum (explainable linear): `analysis.ai` (features, weights, top contributing).
- Final aggregated score: `analysis.final` (default 0.6 rule + 0.4 AI; env: `RULE_W`, `AI_W`).

PDF məzmunu: Title, Summary, Final Risk, Triggered Rules, File Info, AI Top‑3, YARA hits.

### 4.5 Sandbox Native (8050)

Endpoint:
- `POST /run` — `file`, `adapter=strace|firejail|bwrap|nsjail|mock` — trace və stdout/stderr qaytarır.

Qeyd: Hostda alət yoxdursa `status: unavailable`; minimal, no‑net, limitli vaxt.

---

## 5) Frontend UI İstifadəsi

Run (dev):
```bash
cd frontend-ui
npm ci
npm run dev
# http://localhost:5173
```

Env:
- `VITE_API_BASE` (default `http://localhost:8080`)
- `VITE_REPORTER_BASE` (default `http://localhost:8090`)

Səhifələr və xüsusiyyətlər:
- Upload/URL/password; Adapters input (məs: `strace,firejail`).
- Job ID + Auto‑polling + Progress bar.
- Nəticə paneli: Export linkləri (JSON/PDF/STIX), YARA hitləri (filter), IOC görüntüsü, Timeline (trace) filterlər.
- Feedback (Mark FP) və Request Reanalysis düymələri.
- Audit viewer (orchestrator `/audit`).
- RUM + frontend errors backend‑ə göndərilir (Prometheus counter artır).

---

## 6) Monitorinq və Alertlər

Compose ilə Prometheus/Grafana:
- Prometheus `infra/monitoring/prometheus.yml` target-lərə scrape edir.
- Alertlər: `infra/monitoring/alerts.yml` — ServiceDown, OrchestratorHighQueue, DiskUsageHigh (placeholder).
- Grafana (3000): əl ilə datasource/dashboard əlavə et (MVP). İstəsəniz provisioning əlavə oluna bilər.

Metrics URLs:
- Orchestrator: `http://localhost:8080/metrics`
- Reporter: `http://localhost:8090/metrics`
- TI: `http://localhost:8070/metrics`
- Static Analyzer: `http://localhost:8060/metrics`
- Sandbox Native: `http://localhost:8050/metrics`

Logs və Audit:
- Orchestrator audit log: `orchestrator/app/uploads/audit.log` (JSONL), `GET /audit`.
- Compose `docker compose logs` ilə konteyner loglarını topla.

---

## 7) Təhlükəsizlik

- Non‑root icra (USER `svc`), no‑exec storage (fayllar 0600, dirs 0700), safe join (zip‑slip), kvota və retention.
- URL allowlist/blocklist, 30s timeout, retry(3), Content‑Length limit, 10MB fayl limiti.
- Arxiv parol axını; bruteforce YOXDUR; yalnız istifadəçi parolu.

---

## 8) CI/CD və Ansible

- `.github/workflows/`:
  - `ci.yml` — Python xidmətləri install və import yoxlamaları, Node build/test, Docker images build.
  - `python-ci*.yml`, `node-ci.yml`, `compose-e2e.yml` (compose build + smoke).
- Ansible: `ansible/playbook.yml` (stub) — compose ilə ayağa qaldırma istiqamətləndirməsi.

---

## 9) Test Ssenariləri (CLI)

ZIP (şifrəsiz):
```bash
curl -F "file=@test.zip" http://localhost:8080/analyze | jq
curl http://localhost:8080/result/<job_id> | jq
```

ZIP (şifrəli → waiting_password → provide):
```bash
curl -F "file=@secret.zip" http://localhost:8080/analyze | jq
curl http://localhost:8080/result/<job_id> | jq '.state'
curl -H 'Content-Type: application/json' \
  -d '{"job_id":"<job_id>", "password":"infected"}' \
  http://localhost:8080/provide-password | jq
```

URL:
```bash
curl -d 'url=https://example.com/sample.bin' http://localhost:8080/analyze
```

Reporter Demo:
```bash
curl http://localhost:8090/example | jq
```

Static Analyzer Schema:
```bash
curl http://localhost:8060/schema | jq
```

Reporter Schema:
```bash
curl http://localhost:8090/schema | jq
```

---

## 10) GitHub‑a Push (qısa)

```bash
git init
git add -A
git commit -m "ZORBOX MVP"
git remote add origin <GITHUB_REPO_URL>
git branch -M main
git push -u origin main
```

PR axını üçün `.github/PULL_REQUEST_TEMPLATE.md` mövcuddur.

---

## 11) Bonuslar və Limitlər

Bonus:
- REST API (`/analyze`, `/result`) hazırdır.
- STIX, PDF export, YARA, TI, AI‑minimum + rule based aggregation, UI timeline və filterlər.
- OSS sandbox: nsjail/firejail/bwrap/strace (host imkanlarından asılı), Cuckoo/CAPE env ilə inteqrasiya.

Limitlər:
- RAR tam extract üçün OS backend (unrar/bsdtar) lazım ola bilər; hazırda list yalnız backend varsa.
- ISO/IMG yalnız aşkarlanır (extract yoxdur); qrafik vizual timeline minimaldır.
- Grafana provisioning yaml yoxdur (dashboard əl ilə əlavə edilir).

---

## 12) Sürətli FAQ

- “UI export linkləri açılmır” — `VITE_REPORTER_BASE` düzgün qurulduğuna bax; Reporter CORS açıqdır.
- “Şifrəli 7z/zip üçün nə etməli?” — UI-da parol daxil et; Orchestrator `/provide-password` çağıracaq.
- “URL niyə rədd edildi?” — `URL_ALLOWLIST`/`URL_BLOCKLIST` parametrlərinə bax, host pattern uyğun deyil.
- “TI VT işləmədi” — `VT_API_KEY` vermisənmi? 3 hash limit, 8s timeout.

---

## 13) Fayl/Yol İstinadları (seçmə)

- Orchestrator: `orchestrator/app/main.py`, `orchestrator/app/archive.py`, `orchestrator/app/storage.py`
- Static Analyzer: `static-analyzer/app/main.py`, `static-analyzer/app/rules/`, `static-analyzer/app/schema_analyzer.json`
- Reporter: `reporter-service/app/main.py`, `reporter-service/app/pdf.py`, `reporter-service/app/schema_report.json`
- TI: `ti-enrichment/app/main.py`
- Frontend: `frontend-ui/src/App.jsx`, `frontend-ui/README.md`
- Infra Compose: `infra/docker-compose.yml`, `infra/smoke.sh`, `infra/smoke.ps1`
- Infra K8s: `infra/k8s/*.yaml`
- Monitoring: `infra/monitoring/*`

---

Uğurlar! Bu runbook ilə sistemi qura, işə sala və tam end‑to‑end nəticə təqdim edə bilərsiniz. Hər hansı problem yaşasanız, audit və logs hissələrindən kömək alın və yuxarıdakı yoxlama komandaları ilə diaqnostika edin.

