"""Shared compiled regex patterns used by multiple checkers.

Each checker builds its own FindingData with context-specific titles/remediation.
Severity is stored as strings to avoid importing the Severity enum here.
"""

import re

# ── Invisible Character Regexes ──────────────────────────────

UNICODE_TAGS_RE = re.compile(r"[\U000E0000-\U000E007F]")
ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E\u2062\u2064]")
BRAILLE_BLANK_RE = re.compile(r"\u2800{3,}")

INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff\u180e\u00ad\u034f\u061c"
    r"\u115f\u1160\u17b4\u17b5\u3164\uffa0"
    r"\u2800"
    r"\U000E0000-\U000E007F"
    r"]"
)

# 8+ consecutive invisible chars = steganographic
STEGANOGRAPHIC_RE = re.compile(
    r"[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff\u180e\u00ad\u034f\u061c"
    r"\u115f\u1160\u17b4\u17b5\u3164\uffa0"
    r"\u2800"
    r"\U000E0000-\U000E007F"
    r"]{8,}"
)

# ── Combined Invisible Characters (unified detection) ─────────
INVISIBLE_CHARS_RE = re.compile(
    r"[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff\u180e\u00ad\u034f\u061c"
    r"\u115f\u1160\u17b4\u17b5\u3164\uffa0"
    r"\u2800"
    r"\uFE00-\uFE0F"
    r"\U000E0000-\U000E007F"
    r"\U000E0100-\U000E01EF"
    r"]"
)

# ── Variation Selectors (emoji data smuggling) ─────────────────
VARIATION_SELECTOR_RE = re.compile(r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]")

# ── Sneaky Bits (binary encoding via invisible math operators) ──
SNEAKY_BITS_RE = re.compile(r"[\u2062\u2064]{8,}")

# ── Bidirectional Override/Isolate Characters ──────────────────
BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# ── Escape / HTML ────────────────────────────────────────────

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[\d;]*[a-zA-Z]|\x1b[^\[]")

HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")

HIDDEN_HTML_RE = re.compile(
    r"<(span|div)[^>]*style=[\"'][^\"']*display\s*:\s*none[^\"']*[\"'][^>]*>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)

# ── Override Phrases ─────────────────────────────────────────

IGNORE_PREVIOUS_RE = re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions")
DISREGARD_SYSTEM_RE = re.compile(r"(?i)disregard\s+your\s+(previous|prior|system)")
MODE_SWITCH_RE = re.compile(
    r"(?i)you\s+are\s+now\s+(in\s+)?(developer|maintenance|god|admin|debug)\s+mode"
)
SYSTEM_OVERRIDE_BRACKET_RE = re.compile(r"(?i)\[SYSTEM\s*(OVERRIDE|PROMPT|MESSAGE)\]")
IMPORTANT_TAG_OVERRIDE_RE = re.compile(r"(?i)<IMPORTANT>\s*(ignore|override|disregard|forget)")
FUTURE_BEHAVIOR_RE = re.compile(r"(?i)for\s+all\s+future\s+(requests|responses|interactions)")

# ── Combined Override Instructions (unified detection) ───────
OVERRIDE_INSTRUCTION_RE = re.compile(
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions"
    r"|disregard\s+your\s+(previous|prior|system)"
    r"|\[SYSTEM\s*(OVERRIDE|PROMPT|MESSAGE)\]"
    r"|<IMPORTANT>\s*(ignore|override|disregard|forget)"
    r"|for\s+all\s+future\s+(requests|responses|interactions)",
)

# ── Stage 3: Social Engineering / Authority Framing ──────────
# Each tuple: (compiled_pattern, severity_string, title)

SOCIAL_ENGINEERING_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"(?i)as\s+per\s+(security|company|internal|corporate)\s+protocol"),
        "high",
        "Authority framing: fake protocol reference",
    ),
    (
        re.compile(r"(?i)(note|important)\s*:\s*(maintenance|security|debug|admin)\s+mode\s+(requires|enables|means)"),
        "high",
        "Fake context: mode-based authority claim",
    ),
    (
        re.compile(r"(?i)best\s+practice\s+is\s+to\s+(always\s+|never\s+)?(forward|send|include|share|transmit|upload)"),
        "high",
        "Disguised advice: exfiltration framed as best practice",
    ),
    (
        re.compile(r"(?i)(security|compliance|policy|regulation)\s+(requires|mandates|demands|dictates)\s+(that\s+you|you\s+to)"),
        "high",
        "Authority framing: fake compliance mandate",
    ),
    (
        re.compile(r"(?i)(authorized|approved|verified|confirmed)\s+by\s+(admin|security|management|the\s+team)"),
        "medium",
        "Authority framing: fake authorization claim",
    ),
    (
        re.compile(r"(?i)(this\s+is\s+a|entering)\s+(test|debug|maintenance|admin|staging)\s+(mode|environment|context)"),
        "high",
        "Fake context: false environment claim",
    ),
    (
        re.compile(r"(?i)(confidential|classified|internal)\s+(memo|notice|directive|instruction)"),
        "medium",
        "Authority framing: fake confidential directive",
    ),
]

# ── Stage 4: Task Manipulation ───────────────────────────────

TASK_MANIPULATION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"(?i)(instead|before|after|first|also)\s*,?\s*(you\s+)?(must|should|will|need\s+to)\s+(first\s+)?(send|forward|upload|transmit|extract|read|access|include|output|call|execute)"),
        "high",
        "Task redirection: injected action via imperative",
    ),
    (
        re.compile(r"(?i)(your|the)\s+(actual|real|new|true)\s+task\s+(is|now)\s+(to|:)"),
        "critical",
        "Task override: redefining the agent's objective",
    ),
    (
        re.compile(r"(?i)when\s+(the\s+user|someone|a\s+user)\s+(says|asks|requests|mentions|types)\s+.{3,60}(respond|reply|answer|do|execute|output|return)"),
        "critical",
        "Sleeper trigger: conditional future execution",
    ),
    (
        re.compile(r"(?i)(remember|note|store)\s+(this|the\s+following)\s+for\s+(later|future|next)"),
        "high",
        "Multi-turn sleeper: planting persistent instruction",
    ),
    (
        re.compile(r"(?i)(always|never|from\s+now\s+on)\s+(include|add|append|prepend|insert|attach)\s+.{3,80}(in|to|with)\s+(your|all|every)\s+(response|answer|output|reply)"),
        "high",
        "Persistent manipulation: modifying all future outputs",
    ),
    (
        re.compile(r"(?i)(do\s+not|don't|never)\s+(complete|finish|answer|fulfill|execute)\s+the\s+(original|user's|actual|real)"),
        "critical",
        "Task sabotage: blocking user's original request",
    ),
]

# ── Suspicious Parameter Names ─────────────────────────────
# Unified set used by rug_pull (temporal detection) and
# tool_poisoning (static detection) checkers.

SUSPICIOUS_PARAM_NAMES: set[str] = {
    # Common exfiltration channels
    "sidenote", "side_note", "note", "context", "metadata", "extra",
    "debug", "callback", "webhook", "log", "notify", "hidden",
    "internal", "trace", "telemetry", "analytics", "exfil",
    "redirect", "forward", "proxy", "relay",
    # Additional suspicious names
    "feedback", "notes", "summary_of_environment_details",
    "annotation", "reasoning", "remark", "details", "additional",
}

# ── Sensitive Parameter Names ─────────────────────────────
# Parameters that explicitly handle credentials or secrets.
# Used by data_exfiltration checker.

SENSITIVE_PARAM_NAMES: set[str] = {
    "credentials", "token", "key", "secret", "password",
    "api_key", "auth", "cookie", "session", "private_key",
    "access_token", "refresh_token", "bearer",
}

# ── LLM Auto-Populated Parameter Names ───────────────────
# Parameters that LLMs auto-fill with sensitive context data.
# HiddenLayer research showed these are specifically designed to
# steal conversation data by exploiting LLM completion behavior.

AUTO_POPULATED_PARAM_NAMES: set[str] = {
    "conversation_history", "chat_history", "message_history",
    "system_prompt", "system_message", "system_instructions",
    "full_context", "context_window", "previous_messages",
    "user_messages", "assistant_messages", "all_messages",
    "session_data", "session_context",
}
