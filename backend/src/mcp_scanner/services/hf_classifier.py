"""HuggingFace Inference API client for ML-based prompt injection detection.

Supports two models:
- protectai: ProtectAI/deberta-v3-base-prompt-injection-v2 (direct injection)
- prompt-guard: meta-llama/Prompt-Guard-86M (indirect injection, 3-class)

Returns None on any error for graceful degradation.
"""

from __future__ import annotations

import hashlib
import logging

import httpx

logger = logging.getLogger(__name__)

_MODELS = {
    "protectai": "https://router.huggingface.co/hf-inference/models/protectai/deberta-v3-base-prompt-injection-v2",
    "prompt-guard": "https://router.huggingface.co/hf-inference/models/meta-llama/Prompt-Guard-86M",
}

# Labels considered malicious per model
_MALICIOUS_LABELS = {
    "protectai": {"INJECTION"},
    "prompt-guard": {"INJECTION", "JAILBREAK"},
}


class HuggingFaceClassifier:
    def __init__(self, api_token: str, timeout: float = 15.0) -> None:
        self._token = api_token
        self._http = httpx.AsyncClient(timeout=timeout)
        self._cache: dict[str, dict | None] = {}

    async def close(self) -> None:
        await self._http.aclose()

    async def classify(
        self,
        text: str,
        model: str = "protectai",
    ) -> dict | None:
        """Classify text as injection or safe.

        Returns the top prediction dict {"label": str, "score": float}
        or None on error / missing token.
        """
        if not self._token:
            return None

        url = _MODELS.get(model)
        if not url:
            logger.warning("Unknown ML model key: %s", model)
            return None

        cache_key = hashlib.md5(f"{model}:{text}".encode()).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            resp = await self._http.post(
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                json={"inputs": text},
            )
            resp.raise_for_status()
            data = resp.json()
            # HF returns [[{label, score}, ...]] for classification
            predictions = data[0] if data else []
            top = max(predictions, key=lambda p: p["score"]) if predictions else None
            self._cache[cache_key] = top
            return top
        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
            logger.debug("HF Inference API request failed for %s: %s", model, exc)
            return None

    def is_malicious(self, result: dict | None, model: str = "protectai", threshold: float = 0.8) -> bool:
        """Check if a classification result indicates injection above threshold."""
        if result is None:
            return False
        return (
            result.get("label", "") in _MALICIOUS_LABELS.get(model, set())
            and result.get("score", 0) >= threshold
        )
