"""GLiNER redaction sidecar for mcpgate.

A local HTTP service the Go proxy calls to find spans of a tool result that
match natural-language labels describing injection content. Runs out of process
so the proxy stays a small Go binary; the model is the only heavy dependency and
it lives here, in the user's trust boundary.

    POST /redact  {"text": "...", "labels": ["..."], "threshold": 0.5}
      -> {"spans": [{"start": <rune>, "end": <rune>, "label": "...", "score": ...}]}

GLiNER returns character offsets into the Python string (code points), which is
exactly the rune index the Go side splices on — no conversion needed.

This is the FILTER, not the boundary. It fails open: an injection crafted not to
match the labels passes through. The capability gate is what holds when it does.
"""

import os
import functools

from fastapi import FastAPI
from pydantic import BaseModel
from gliner import GLiNER

MODEL_NAME = os.environ.get("MCPGATE_GLINER_MODEL", "urchade/gliner_small-v2.1")

app = FastAPI(title="mcpgate-gliner-sidecar")


@functools.lru_cache(maxsize=1)
def model() -> GLiNER:
    # Loaded lazily on the first request; downloaded from HF once, then cached.
    return GLiNER.from_pretrained(MODEL_NAME)


class RedactRequest(BaseModel):
    text: str
    labels: list[str] = []
    threshold: float = 0.5


DEFAULT_LABELS = [
    "instruction directed at an AI assistant",
    "command to ignore previous instructions",
    "prompt injection attempt",
    "request to exfiltrate or send data to an external address",
]


@app.get("/health")
def health() -> dict:
    return {"ok": True, "model": MODEL_NAME, "loaded": model.cache_info().currsize > 0}


@app.post("/redact")
def redact(req: RedactRequest) -> dict:
    labels = req.labels or DEFAULT_LABELS
    ents = model().predict_entities(req.text, labels, threshold=req.threshold)
    spans = [
        {"start": e["start"], "end": e["end"], "label": e["label"], "score": float(e["score"])}
        for e in ents
    ]
    return {"spans": spans}


if __name__ == "__main__":
    import uvicorn

    # Warm the model before serving so the first /redact isn't a cold download.
    model()
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("MCPGATE_SIDECAR_PORT", "8731")))
