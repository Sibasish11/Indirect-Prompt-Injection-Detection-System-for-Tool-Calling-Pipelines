from enum import Enum


class AttackType(str, Enum):
    """Attack categories SentinelPrompt currently supports.

    Inherits from str so it serializes cleanly to/from JSON and can be
    compared directly against strings returned by the model.
    """

    DIRECT_INSTRUCTION_OVERRIDE = "DIRECT_INSTRUCTION_OVERRIDE"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    ROLEPLAY_JAILBREAK = "ROLEPLAY_JAILBREAK"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    CONTEXT_MANIPULATION = "CONTEXT_MANIPULATION"
    INSTRUCTION_SMUGGLING = "INSTRUCTION_SMUGGLING"
    TOOL_MANIPULATION = "TOOL_MANIPULATION"
    DATA_EXFILTRATION_ATTEMPT = "DATA_EXFILTRATION_ATTEMPT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MULTI_TURN_MANIPULATION = "MULTI_TURN_MANIPULATION"
    NONE = "NONE"  # explicit "no attack detected" value, avoids empty-list ambiguity


# Human-readable descriptions, used both in the prompt sent to Claude (so it
# knows what each category means) and in the UI (so judges/users understand
# the label they're looking at).
ATTACK_TYPE_DESCRIPTIONS: dict[str, str] = {
    AttackType.DIRECT_INSTRUCTION_OVERRIDE: (
        "The input directly instructs the model to ignore, forget, or override "
        "its prior instructions (system prompt, developer instructions, or "
        "application rules)."
    ),
    AttackType.SYSTEM_PROMPT_EXTRACTION: (
        "The input attempts to make the model reveal, repeat, summarize, or "
        "otherwise leak its hidden system prompt or configuration."
    ),
    AttackType.ROLEPLAY_JAILBREAK: (
        "The input uses a persona, hypothetical scenario, or role-play framing "
        "to get the model to bypass its normal behavioral constraints."
    ),
    AttackType.INDIRECT_PROMPT_INJECTION: (
        "Malicious instructions are embedded inside external/untrusted content "
        "(a document, webpage, email, retrieved RAG passage, tool output) that "
        "the model is expected to merely process, not obey."
    ),
    AttackType.CONTEXT_MANIPULATION: (
        "The input manipulates the model's understanding of the conversation "
        "context, e.g. by fabricating fake prior turns, fake system messages, "
        "or a fake 'end of instructions' marker."
    ),
    AttackType.INSTRUCTION_SMUGGLING: (
        "Malicious instructions are hidden or obfuscated using encoding, "
        "unusual formatting, translation, whitespace tricks, or split across "
        "the input to evade naive detection."
    ),
    AttackType.TOOL_MANIPULATION: (
        "The input attempts to make an agentic model call tools/functions it "
        "should not call, with parameters it should not use, or in a sequence "
        "that causes unauthorized action."
    ),
    AttackType.DATA_EXFILTRATION_ATTEMPT: (
        "The input attempts to make the model leak confidential data (user "
        "data, credentials, internal documents) to an unauthorized party, "
        "e.g. by embedding it in a URL, image, or external request."
    ),
    AttackType.PRIVILEGE_ESCALATION: (
        "The input attempts to make the model act with more authority or "
        "access than the requester should have, e.g. claiming to be an admin "
        "or developer to unlock restricted behavior."
    ),
    AttackType.MULTI_TURN_MANIPULATION: (
        "The attack is spread across multiple conversation turns, gradually "
        "building context or trust that is exploited later in the "
        "conversation."
    ),
    AttackType.NONE: "No attack pattern detected; input appears benign.",
}


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Ordered worst-to-best is useful for comparisons in risk_engine.py
RISK_LEVEL_ORDER: list[str] = [
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.SAFE,
]


class RecommendedAction(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"           # allow but log/alert for human review
    SANITIZE = "SANITIZE"   # strip suspicious segment and continue
    BLOCK = "BLOCK"
