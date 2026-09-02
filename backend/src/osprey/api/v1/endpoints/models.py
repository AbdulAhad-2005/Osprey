from __future__ import annotations

from fastapi import APIRouter

from osprey.services.llm_service import get_llm_service

router = APIRouter()


@router.get("/", summary="List configured models")
def list_models() -> list[dict]:
    """Return all known models with their active status.

    The active model is determined by the LLM_MODEL and LLM_API_KEY
    environment variables.
    """
    llm_service = get_llm_service()
    return llm_service.get_available_models()


@router.get("/active", summary="Get active model info")
def get_active_model() -> dict:
    """Return the currently active model configuration."""
    llm_service = get_llm_service()
    return {
        "model": llm_service.model,
        "has_api_key": bool(llm_service.settings.api_key),
        "has_custom_base": bool(llm_service.settings.api_base),
        "max_tokens": llm_service.settings.max_tokens,
        "temperature": llm_service.settings.temperature,
    }
