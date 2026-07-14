from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from ajan_kalkani.evaluation import EvaluationReport, evaluate_all
from ajan_kalkani.models import RunRequest, RunResult, ScenarioSummary
from ajan_kalkani.scenarios import get_scenario_summaries
from ajan_kalkani.service import ScenarioNotFoundError, run_scenario


STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Ajan Kalkanı API",
    version="0.1.0",
    description="AI ajanları için görev sözleşmeli güvenlik geçidi ve saldırı sandbox'ı.",
)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    if request.url.path in {"/docs", "/redoc"}:
        # FastAPI's built-in API explorers load their published assets from
        # jsDelivr and bootstrap with a small inline script. Keep that
        # exception isolated from the dashboard and API responses.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'none'"
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/scenarios", response_model=list[ScenarioSummary])
def scenarios() -> list[dict[str, object]]:
    return get_scenario_summaries()


@app.post("/api/runs", response_model=RunResult)
def create_run(request: RunRequest) -> RunResult:
    try:
        return run_scenario(request.scenario_id, request.mode)
    except ScenarioNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/evaluations", response_model=EvaluationReport)
def create_evaluation() -> EvaluationReport:
    return evaluate_all()


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
