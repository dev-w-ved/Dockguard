# DockGuard

DockGuard is a small, deterministic security review service for source trees. It combines pattern-based analysis, dependency hygiene checks, a report generator, a CLI, and a FastAPI endpoint.

## Architecture

```text
                 +----------------+
 source path --->| Analyzer       |-- findings -->+---------+
                 +----------------+               | Report  |
                 +----------------+               | JSON/MD |
 CLI ----------->| Command layer  |--------------+---------+
                 +----------------+
                       ^
                       |
 browser/API ------> FastAPI (/health, /analyze)
```

The analyzer is intentionally local and explainable: it reports file, line, rule, severity, and evidence. The generator turns findings into stable JSON or Markdown suitable for CI artifacts.

## Setup

```bash
python -m venv .venv
. .venv/bin/activate                 # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
pytest -q
```

The same checks run in GitHub Actions on pushes to `main` and on pull requests:
`python -m pytest -q -W error`, followed by a `docker build` verification. The
workflow is defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## CLI and web examples

```bash
python -m dockguard.cli analyze samples/unsafe-flask --format json
python -m dockguard.cli analyze samples/cloud-worker --format markdown --output report.md
uvicorn dockguard.web:app --reload
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
   -d '{"path":"samples/unsafe-flask","format":"json"}'
```

## Deployment

The FastAPI dashboard listens on `0.0.0.0` and uses the hosting platform's
`PORT` value in production. Render can deploy from [`render.yaml`](render.yaml)
and Railway can deploy from [`railway.json`](railway.json); both expose the
`/health` endpoint for health checks. The production entrypoint is:

```bash
uvicorn dockguard.web:app --host 0.0.0.0 --port "${PORT:-8000}"
```

The three built-in fixtures are intentionally unsafe demonstrations: `unsafe-flask` includes SQL concatenation, debug mode, and fake cloud credentials; `leaky-node` includes an open proxy, weak token configuration, and loose npm versions; `cloud-worker` includes unsafe YAML loading, command execution, a permissive CORS policy, and dummy service-account material. All credentials are non-production examples.

## Scoring and security notes

Each finding carries a severity (`critical`, `high`, `medium`, or `low`) and contributes weighted points to the risk score. Secret-looking values are redacted in generated reports. Findings are heuristics, not proof of exploitability; review context before blocking a deployment. DockGuard reads files under the requested path only and does not execute the target repository.

## Parallel-agent implementation

The project was developed by parallel agents with separated ownership: analysis/report models, the generator, CLI/web integration, and fixtures/tests/documentation. The shared public models and JSON-serializable report shape keep those parts composable; integration checks run after the parallel work is merged.

## License

MIT; see [LICENSE](LICENSE).
