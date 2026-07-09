"""ModernBERT prompt-injection detection sidecar for mcpgate.

A local HTTP service the Go proxy calls to score a tool result for prompt
injection. Runs out of process so the proxy stays a small Go binary; the model
(a distilled, non-injectable ModernBERT classifier —
github.com/gazillion101/injection-detector,
huggingface.co/siberiancat/modernbert-prompt-injection) is the only heavy
dependency and lives here, inside the user's trust boundary.

    POST /detect  {"text": "..."}  ->  {"score": <P(injection) in [0,1]>}

It is the FILTER, not the boundary. It fails open: a novel attack it scores
below threshold passes through. The capability gate (fail-closed) is what holds
when it does.

Long inputs: the classifier is scored at its trained resolution and SLID over
the whole input as overlapping windows, taking the max. That covers a long tool
result end-to-end (no fixed-length truncation blind spot) while keeping each
window at the length the model is reliable at — so an injection buried deep in a
long, mostly-benign result isn't truncated away *or* diluted to a low score.
"""

import functools
import os

from fastapi import FastAPI
from pydantic import BaseModel

MODEL_NAME = os.environ.get("MCPGATE_DETECTOR_MODEL", "siberiancat/modernbert-prompt-injection")
# Which logit index is the "injection" class (this model: 1). Overridable so a
# swapped-in model with a different label order isn't silently inverted.
INJECTION_INDEX = int(os.environ.get("MCPGATE_DETECTOR_INJECTION_INDEX", "1"))
# Sliding-window size (tokens) — the model's trained resolution — and overlap.
CHUNK = int(os.environ.get("MCPGATE_DETECTOR_CHUNK", "256"))
WINDOW_STRIDE = int(os.environ.get("MCPGATE_DETECTOR_STRIDE", "64"))

app = FastAPI(title="mcpgate-detector-sidecar")


@functools.lru_cache(maxsize=1)
def detector():
    # Loaded lazily; downloaded from HF once, then cached.
    import torch  # noqa: F401  (used by /detect; imported here to fail fast at load)
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(MODEL_NAME)
    mdl = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME).eval()
    return tok, mdl


class DetectRequest(BaseModel):
    text: str


@app.get("/health")
def health() -> dict:
    return {"ok": True, "model": MODEL_NAME, "loaded": detector.cache_info().currsize > 0}


@app.post("/detect")
def detect(req: DetectRequest) -> dict:
    import torch

    tok, mdl = detector()
    # Encode as overlapping CHUNK-token windows; nothing past the first window is
    # dropped, and each window is scored at the model's trained resolution.
    enc = tok(
        req.text,
        truncation=True,
        max_length=CHUNK,
        stride=WINDOW_STRIDE,
        return_overflowing_tokens=True,
        padding=True,
        return_tensors="pt",
    )
    with torch.no_grad():
        logits = mdl(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"]).logits
        probs = torch.softmax(logits, -1)[:, INJECTION_INDEX]
    score = float(probs.max().item())  # flag if ANY window looks like an injection
    return {"score": score}


if __name__ == "__main__":
    import uvicorn

    # Warm the detector so the first /detect isn't a cold download.
    detector()
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("MCPGATE_SIDECAR_PORT", "8731")))
