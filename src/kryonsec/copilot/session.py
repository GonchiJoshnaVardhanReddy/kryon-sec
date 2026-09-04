"""Copilot session: STM with Strix-style compaction (spec v2.1.1 §3.4, §6.4)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..config import KryonsecConfig
from ..llm import chat, compaction_model_for, count_tokens
from ..secrets import redact, restore

log = logging.getLogger(__name__)

COMPACTION_PROMPT = (
    "Summarize the following conversation history. Be EXHAUSTIVE, not concise.\n"
    "Rules:\n"
    "- Enumerate every distinct item as its own bullet\n"
    "- Copy exact values VERBATIM: URLs, file paths, CVE IDs, version numbers, commands\n"
    "- Secrets appear only as placeholders («SECRET_n»); copy them verbatim\n"
    "- Preserve the sequence of events\n"
    "- Include the outcome of every tool call\n"
)


@dataclass
class Message:
    role: str
    content: str

    def as_dict(self) -> dict:
        return {"role": self.role, "content": self.content}


@dataclass
class GeneralSession:
    cfg: KryonsecConfig
    messages: list[Message] = field(default_factory=list)
    token_estimate: int = 0

    # ---- STM bookkeeping -------------------------------------------------

    def _recount(self) -> None:
        serialized = "\n".join(m.content for m in self.messages)
        self.token_estimate = count_tokens(serialized)

    def add(self, role: str, content: str) -> None:
        self.messages.append(Message(role=role, content=content))
        self._recount()
        if len(self.messages) > self.cfg.max_messages:
            # hard cap on message count before token compaction kicks in
            self.messages = self.messages[-self.cfg.max_messages :]

    def as_llm_messages(self, system_prompt: str) -> list[dict]:
        out = [{"role": "system", "content": system_prompt}]
        out.extend(m.as_dict() for m in self.messages)
        return out

    # ---- Compaction (spec §3.4 + §6.4) -----------------------------------

    async def maybe_compact(self) -> None:
        """Compact when tokens exceed the trigger ratio (default 80%)."""
        self._recount()
        threshold = int(self.cfg.max_session_tokens * self.cfg.compaction_trigger_ratio)
        if self.token_estimate <= threshold:
            return

        head, recent = self._split_at_budget()
        if not head:
            return

        import json as _json
        redacted_head = "\n".join(_json.dumps(m.as_dict()) for m in head)
        redacted_text, secret_map = redact(redacted_head)
        secrets_present = bool(secret_map)
        model = compaction_model_for(self.cfg, secrets_present)

        summary = chat(
            self.cfg,
            [{"role": "user", "content": COMPACTION_PROMPT + "\nMessages to summarize:\n" + redacted_text}],
            model=model,
            # Secrets present => local model ONLY, never a third-party
            # fallback, even when the local model is down (spec §6.4).
            local_only=secrets_present,
        )
        if secrets_present:
            summary = restore(summary, secret_map)

        checkpoint = Message(
            role="system",
            content=f"[SESSION CHECKPOINT]\n{summary}",
        )
        self.messages = [checkpoint] + recent
        self._recount()
        log.info(
            "compacted session: %d messages -> checkpoint + %d recent (secrets: %s)",
            len(head), len(recent), secrets_present,
        )

    def _split_at_budget(self) -> tuple[list[Message], list[Message]]:
        """Split so the recent tail keeps up to ~compaction_keep_tokens —
        but never more than half the messages, so the head is non-empty
        whenever compaction has been triggered."""
        keep_tokens = self.cfg.compaction_keep_tokens
        max_keep_msgs = max(1, len(self.messages) // 2)
        kept: list[Message] = []
        used = 0
        for msg in reversed(self.messages):
            if len(kept) >= max_keep_msgs:
                break
            cost = count_tokens(msg.content)
            if kept and used + cost > keep_tokens:
                break
            kept.append(msg)
            used += cost
        kept.reverse()
        split = len(self.messages) - len(kept)
        return self.messages[:split], self.messages[split:]
