# Frontend UI (MVP)

Vite + React app with upload/status/report/feedback. Includes basic RUM and error logging stubs.

## Scripts
- `npm run dev` — start dev server
- `npm run build` — build
- `npm test` — unit tests (Vitest)

## Pages
- Upload (file/URL, archive password)
- Jobs (status list)
- Job Detail (JSON/PDF/STIX links, timeline/IOC/YARA panel, feedback)

## Notes
- Configure API base via `VITE_API_BASE` env.
- RUM metrics + frontend errors are sent to orchestrator (`/frontend-rum`, `/frontend-errors`).
- Max upload size: 10 MB (enforced by backend). Archive password supported for ZIP/7z/RAR.
- Export links resolve via `VITE_REPORTER_BASE`.

## Tests
- Run `npm test` (Vitest). Includes a basic render test. Add tests for filters and timeline rendering as needed.

## PR Template
- Repository-wide PR template exists at `.github/PULL_REQUEST_TEMPLATE.md`.
