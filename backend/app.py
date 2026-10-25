"""Thin, synchronous subprocess adapter; FastAPI runs it in its worker thread pool."""
import json
import logging
import math
import os
from pathlib import Path
import subprocess

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from backend.models import AnalyzeRequest, AnalyzeResponse

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]


def create_app(*, engine_path: Path | None = None, timeout: float | None = None) -> FastAPI:
    executable = (engine_path or Path(os.environ.get("THREATGRAPH_ENGINE", ROOT / "build" / "threatgraph_engine"))).resolve()
    engine_timeout = timeout if timeout is not None else float(os.environ.get("THREATGRAPH_TIMEOUT_SECONDS", "5"))
    if not math.isfinite(engine_timeout) or engine_timeout <= 0:
        raise ValueError("Engine timeout must be finite and positive")

    app = FastAPI(title="ThreatGraph API", version="0.2.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["POST"],
        allow_headers=["Content-Type"],
    )

    @app.post("/api/analyze", response_model=AnalyzeResponse)
    def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
        try:
            process = subprocess.run(
                [str(executable)],
                input=json.dumps(request.engine_payload()),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=engine_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(504, detail={"code": "engine_timeout", "message": "Graph analysis exceeded its time limit"}) from None
        except OSError:
            logger.exception("Cannot launch ThreatGraph engine")
            raise HTTPException(503, detail={"code": "engine_unavailable", "message": "Graph engine is unavailable; check the build and engine path"}) from None
        except UnicodeError:
            raise HTTPException(502, detail={"code": "invalid_engine_output", "message": "Graph engine returned invalid output"}) from None

        if process.returncode != 0:
            logger.error("Graph engine failed with exit code %s", process.returncode)
            raise HTTPException(502, detail={"code": "engine_failed", "message": "Graph engine failed to analyze a validated request"})
        try:
            return AnalyzeResponse.model_validate_json(process.stdout)
        except ValidationError:
            raise HTTPException(502, detail={"code": "invalid_engine_output", "message": "Graph engine returned invalid output"}) from None

    return app


app = create_app()
