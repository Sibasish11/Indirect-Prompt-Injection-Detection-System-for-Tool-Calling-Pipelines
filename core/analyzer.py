from __future__ import annotations

import os
import time

import openai

from core.prompts import SENTINEL_SYSTEM_PROMPT, build_analysis_user_prompt
from core.validator import AnalysisResult, make_fallback_result, parse_and_validate

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

MODEL = os.environ.get(
    "OPENROUTER_MODEL", "openai/gpt-oss-20b:free"
)

MAX_TOKENS = 1500
MAX_RETRIES = 2
RETRY_BASE_DELAY_SECONDS = 1.5

# Rough safety cap so a giant pasted document doesn't blow the context
# window or the budget for a hackathon demo. Real production systems would
# chunk long content instead of truncating.
MAX_INPUT_CHARS = 20_000


def _get_client() -> openai.OpenAI:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not set. Copy .env.example to .env and "
            "add your OpenRouter API key from https://openrouter.ai/keys."
        )
    return openai.OpenAI(
        api_key=api_key,
        base_url=OPENROUTER_BASE_URL,
        default_headers={
            "HTTP-Referer": "http://localhost:8501",
            "X-Title": "SentinelPrompt",
        },
    )


def _truncate(text: str, limit: int = MAX_INPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n[... content truncated for analysis ...]"


def analyze(
    application_instructions: str | None,
    external_content: str,
    conversation_context: str | None = None,
) -> AnalysisResult:
    """Runs a single prompt-injection analysis and returns a validated
    AnalysisResult. Never raises -- API/network/rate-limit errors are
    converted into a fallback AnalysisResult so the UI always has
    something sensible to show.
    """
    if not external_content or not external_content.strip():
        return make_fallback_result("No content was provided to analyze.")

    try:
        client = _get_client()
    except RuntimeError as e:
        return make_fallback_result(str(e))

    user_prompt = build_analysis_user_prompt(
        application_instructions=_truncate(application_instructions or ""),
        external_content=_truncate(external_content),
        conversation_context=_truncate(conversation_context or ""),
    )

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                messages=[
                    {"role": "system", "content": SENTINEL_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            raw_text = response.choices[0].message.content or ""
            return parse_and_validate(raw_text)

        except openai.RateLimitError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BASE_DELAY_SECONDS * (2**attempt))
                continue
            return make_fallback_result(
                "Rate limit exceeded after retries. Please wait and try "
                "again."
            )

        except openai.APIConnectionError as e:
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BASE_DELAY_SECONDS * (2**attempt))
                continue
            return make_fallback_result(
                "Could not connect to OpenRouter. Check your network "
                "connection."
            )

        except openai.AuthenticationError as e:
            last_error = e
            return make_fallback_result(
                "Authentication failed. Check that OPENROUTER_API_KEY is valid."
            )

        except openai.APIStatusError as e:
            last_error = e
            if e.status_code == 400:
                return make_fallback_result(
                    "OpenRouter rejected the request (400). Check that the "
                    "model is available and supports chat completions."
                )
            if e.status_code == 403:
                return make_fallback_result(
                    "OpenRouter denied access (403). Check the API key and "
                    "model availability."
                )
            if e.status_code == 404:
                return make_fallback_result(
                    f"OpenRouter could not find model '{MODEL}' (404). "
                    "Choose a currently available chat model, preferably "
                    "one ending in :free."
                )
            return make_fallback_result(
                f"OpenRouter returned an error (status {e.status_code})."
            )

        except Exception as e:  # noqa: BLE001 - last-resort safety net
            last_error = e
            return make_fallback_result(f"Unexpected error during analysis: {e}")

    return make_fallback_result(f"Analysis failed after retries: {last_error}")
