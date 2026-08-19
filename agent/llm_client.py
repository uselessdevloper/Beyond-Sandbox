import os
import re
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, Tuple

DEFAULT_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "")
DEFAULT_OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "120.0"))

def get_available_ollama_models(host: str = DEFAULT_OLLAMA_HOST, timeout: float = 3.0) -> list:
    """Fetch list of locally installed Ollama models on the local system."""
    try:
        req = urllib.request.Request(
            f"{host}/api/tags",
            headers={"User-Agent": "CyberSandbox-Local/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name") for m in data.get("models", []) if m.get("name")]
            return models
    except Exception:
        return []

def get_active_provider() -> Tuple[str, str]:
    """
    Determines the active local LLM provider and model.
    Returns (provider, model_name).
    Providers: 'ollama', 'mock'
    """
    configured_provider = os.environ.get("LLM_PROVIDER", "auto").strip().lower()

    if configured_provider == "mock":
        return "mock", "rule-based-mock"

    if configured_provider == "ollama":
        models = get_available_ollama_models(DEFAULT_OLLAMA_HOST)
        model = DEFAULT_OLLAMA_MODEL or (models[0] if models else "qwen3:8b")
        return "ollama", model

    # Auto mode: Check if local Ollama daemon is running on local system
    models = get_available_ollama_models(DEFAULT_OLLAMA_HOST)
    if models or DEFAULT_OLLAMA_MODEL:
        model = DEFAULT_OLLAMA_MODEL or (models[0] if models else "qwen3:8b")
        return "ollama", model

    # Fallback to local deterministic mock
    return "mock", "rule-based-mock"

def _clean_llm_response(text: str) -> str:
    """Strip thinking traces (<think>...</think>) and leading/trailing whitespace."""
    if not text:
        return ""
    # Remove <think>...</think> tags used by reasoning models (DeepSeek-R1, Qwen etc.)
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    return cleaned.strip()

def _query_ollama(
    prompt: str,
    model: str,
    host: str = DEFAULT_OLLAMA_HOST,
    timeout: float = DEFAULT_OLLAMA_TIMEOUT,
    response_format: Optional[str] = None,
) -> Optional[str]:
    """Send generation prompt strictly to local Ollama instance (127.0.0.1)."""
    url = f"{host}/api/generate"
    payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 4096,
        }
    }
    if response_format == "json":
        payload["format"] = "json"

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "CyberSandbox-Local/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            raw_text = res_json.get("response", "")
            return _clean_llm_response(raw_text)
    except Exception as exc:
        print(f"  [llm_client] Local Ollama query failed ({exc})")
        return None

def query_llm(
    prompt: str,
    timeout: float = DEFAULT_OLLAMA_TIMEOUT,
    response_format: Optional[str] = None,
) -> Tuple[Optional[str], str]:
    """
    Query the local LLM provider (Ollama / Local Engine).
    Returns (raw_response_text, provider_info_str).
    """
    provider, model = get_active_provider()

    if provider == "ollama":
        res = _query_ollama(prompt, model=model, timeout=timeout, response_format=response_format)
        if res is not None:
            return res, f"ollama ({model})"
        return None, "mock"

    return None, "mock"
