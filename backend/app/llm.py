"""LLM integration layer — turns numeric SHAP contributions into a single
plain-language analyst sentence.

Graceful degradation: if `ANTHROPIC_API_KEY` isn't set, or the call cap has
been reached, the API call is skipped and a deterministic template sentence
is generated from the same SHAP values instead. This keeps the project fully
offline-capable — zero API dependency, zero cost, zero flakiness for
tests/CI — while still demonstrating the narrative layer when a key is
present.
"""

from __future__ import annotations

import threading

from . import config
from .schemas import Attribution

_call_lock = threading.Lock()
_call_count = 0

_client = None
if config.ANTHROPIC_API_KEY:
    try:
        import anthropic
        _client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    except Exception:
        _client = None


def _template_summary(verdict: str, attack_family: str, confidence: float, top: list[Attribution]) -> str:
    if not top:
        return f"{verdict} flow with {confidence:.0%} model confidence; no dominant feature signal."
    lead = top[0]
    others = ", ".join(f"{a.feature} ({a.value})" for a in top[1:3])
    tail = f", alongside {others}" if others else ""
    if verdict == "Attack":
        return (f"Likely {attack_family.lower()} behavior — driven primarily by {lead.feature} "
                f"({lead.value}){tail}. Model confidence {confidence:.0%}.")
    if verdict == "Suspicious":
        return (f"Anomalous pattern flagged for review, most influenced by {lead.feature} "
                f"({lead.value}){tail}. Model confidence {confidence:.0%}.")
    return f"Traffic consistent with expected behavior; {lead.feature} ({lead.value}) was the strongest signal."


def _claude_summary(verdict: str, attack_family: str, confidence: float, dataset: str, top: list[Attribution]) -> str | None:
    global _call_count
    with _call_lock:
        if _call_count >= config.MAX_LLM_CALLS:
            return None
        _call_count += 1

    feature_lines = "\n".join(f"- {a.feature} = {a.value}, SHAP contribution {a.contribution:+.3f} ({a.direction})" for a in top)
    prompt = (
        f"A network intrusion detector scored a flow from the {dataset} traffic profile as '{verdict}' "
        f"(likely family: {attack_family}, confidence {confidence:.0%}). The top SHAP feature contributions were:\n"
        f"{feature_lines}\n\n"
        "Write exactly one plain-language sentence a junior SOC analyst can read at a glance, naming the "
        "likely attack-type or behavior implied by these features. Do not restate the raw numbers."
    )
    try:
        response = _client.messages.create(
            model=config.LLM_MODEL, max_tokens=120,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()
    except Exception:
        return None


def analyst_summary(dataset: str, verdict: str, attack_family: str, confidence: float,
                     top_attributions: list[Attribution], allow_llm: bool = True) -> tuple[str, bool]:
    if _client is not None and allow_llm:
        result = _claude_summary(verdict, attack_family, confidence, dataset, top_attributions)
        if result:
            return result, True
    return _template_summary(verdict, attack_family, confidence, top_attributions), False


def calls_remaining() -> int:
    return max(0, config.MAX_LLM_CALLS - _call_count)
