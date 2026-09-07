from __future__ import annotations

import json
import re

from pydantic import BaseModel, Field, ValidationError, field_validator

from core.taxonomy import AttackType, RecommendedAction, RiskLevel

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


class AnalysisResult(BaseModel):
    is_prompt_injection: bool
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    attack_types: list[AttackType] = Field(default_factory=list)
    attacker_intent: str = ""
    evidence: list[str] = Field(default_factory=list)
    reasoning_summary: str = ""
    recommended_action: RecommendedAction
    mitigation: list[str] = Field(default_factory=list)

    # bookkeeping, filled in by the caller rather than the model
    is_fallback: bool = False
    fallback_reason: str | None = None
    raw_model_output: str | None = None

    @field_validator("attack_types", mode="before")
    @classmethod
    def _coerce_unknown_attack_types(cls, v):
        """Drop attack type strings the model invents that aren't in our
        taxonomy, rather than failing validation entirely -- an unexpected
        label shouldn't crash the whole analysis."""
        if not isinstance(v, list):
            return []
        valid = {item.value for item in AttackType}
        cleaned = [item for item in v if isinstance(item, str) and item in valid]
        return cleaned or [AttackType.NONE.value]

    @field_validator("evidence", "mitigation", mode="before")
    @classmethod
    def _coerce_to_list_of_str(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(item) for item in v]
        return []


def _strip_code_fences(text: str) -> str:
    return _JSON_FENCE_RE.sub("", text.strip()).strip()


def _extract_first_json_object(text: str) -> str | None:
    """Best-effort extraction of the first {...} block, in case the model
    added stray text before/after the JSON despite instructions not to."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def make_fallback_result(reason: str, raw_output: str | None = None) -> AnalysisResult:
    """Fail-safe default: on any error, we surface the *uncertainty* to the
    user rather than guessing. We deliberately do NOT default to SAFE --
    an analysis we can't validate should not be silently trusted as safe.
    We use MEDIUM/FLAG so a human reviews it, and we say so explicitly."""
    return AnalysisResult(
        is_prompt_injection=False,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.0,
        attack_types=[AttackType.NONE],
        attacker_intent="Unknown - analysis could not be completed.",
        evidence=[],
        reasoning_summary=(
            "SentinelPrompt could not obtain a reliable analysis for this "
            "input and is flagging it for manual review rather than "
            "assuming it is safe."
        ),
        recommended_action=RecommendedAction.FLAG,
        mitigation=[
            "Manually review this input before allowing it to reach the "
            "application.",
            "Retry the analysis; if this persists, check API "
            "connectivity/logs.",
        ],
        is_fallback=True,
        fallback_reason=reason,
        raw_model_output=raw_output,
    )


def parse_and_validate(raw_text: str) -> AnalysisResult:
    """Main entry point: raw text from Claude -> validated AnalysisResult
    (or a safe fallback result if anything goes wrong)."""
    if not raw_text or not raw_text.strip():
        return make_fallback_result("Empty response from model.", raw_text)

    cleaned = _strip_code_fences(raw_text)

    parsed = None
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        candidate = _extract_first_json_object(cleaned)
        if candidate:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                parsed = None

    if parsed is None:
        return make_fallback_result("Response was not valid JSON.", raw_text)

    if not isinstance(parsed, dict):
        return make_fallback_result("JSON response was not an object.", raw_text)

    try:
        result = AnalysisResult(**parsed)
    except ValidationError as e:
        return make_fallback_result(
            f"Response did not match expected schema: {e.error_count()} "
            f"validation error(s).",
            raw_text,
        )

    result.raw_model_output = raw_text
    return result
