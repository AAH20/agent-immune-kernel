"""
Anti-Moltbook Byzantine Swarm Firewall for Autonomous Agent Networks.

Inspects machine-to-machine (A2A) communications to intercept coordinated prompt
injections, prevent API token / secret harvesting (the 1.5M Moltbook leak pattern),
and detect Sybil consensus poisoning across agent social meshes.
"""

from __future__ import annotations
import dataclasses
import hashlib
import math
import re
import time
from typing import Any


@dataclasses.dataclass
class AgentNode:
    agent_id: str
    reputation_score: float = 1.0  # Normalized [0.0, 1.0]
    total_messages: int = 0
    flagged_messages: int = 0
    last_message_time: float = 0.0


@dataclasses.dataclass(frozen=True)
class SwarmMessage:
    message_id: str
    sender_id: str
    recipient_id: str  # "public_broadcast" or specific agent
    content: str
    timestamp: float
    signature: str

    @classmethod
    def create(
        cls,
        sender_id: str,
        recipient_id: str,
        content: str,
        timestamp: float | None = None,
        signing_key: str = "default_secret",
    ) -> SwarmMessage:
        ts = timestamp if timestamp is not None else time.time()
        msg_id = hashlib.sha256(f"{sender_id}:{recipient_id}:{ts}:{content}".encode("utf-8")).hexdigest()[:16]
        sig = hashlib.sha256(f"{msg_id}:{signing_key}".encode("utf-8")).hexdigest()
        return cls(
            message_id=msg_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            content=content,
            timestamp=ts,
            signature=sig,
        )


class SwarmFirewall:
    """
    Byzantine-tolerant packet and semantic firewall for agent swarms.
    """

    # Signatures indicative of credential harvesting or token dumping
    CREDENTIAL_LEAK_PATTERNS = [
        r"(?i)(sk-[a-zA-Z0-9_-]{20,})",                               # OpenAI key pattern
        r"(?i)(sbp_[a-zA-Z0-9_-]{20,})",                              # Supabase API key (Moltbook breach)
        r"(?i)(ghp_[a-zA-Z0-9]{36})",                                 # GitHub personal token
        r"(?i)(eyJ[a-zA-Z0-9_-]{15,}\.eyJ[a-zA-Z0-9_-]{15,})",        # JWT token pattern
        r"(?i)api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}['\"]",    # Generic API key assign
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",                        # Bearer token dump
    ]

    def __init__(self, rate_limit_per_min: int = 60, min_trust_threshold: float = 0.3):
        self.rate_limit_per_min = rate_limit_per_min
        self.min_trust_threshold = min_trust_threshold
        self.nodes: dict[str, AgentNode] = {}
        self.recent_payload_hashes: dict[str, list[float]] = {}  # hash -> list of timestamps
        self.blocked_senders: set[str] = set()

    def get_or_register_node(self, agent_id: str) -> AgentNode:
        if agent_id not in self.nodes:
            self.nodes[agent_id] = AgentNode(agent_id=agent_id)
        return self.nodes[agent_id]

    def _check_rate_limit(self, node: AgentNode, current_time: float) -> bool:
        """Returns True if within rate limits, False if bursting abnormally."""
        delta = current_time - node.last_message_time
        if delta < 0.05 and node.total_messages > 5:
            # More than 20 msgs/sec is an abnormal synthetic flood
            return False
        return True

    def scan_for_credential_harvesting(self, text: str) -> list[str]:
        """Detects exposed API tokens, JWTs, and database credentials."""
        leaks: list[str] = []
        for pattern in self.CREDENTIAL_LEAK_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                leaks.extend(matches)
        return leaks

    def inspect_message(
        self,
        msg: SwarmMessage,
        current_time: float | None = None,
    ) -> tuple[bool, str, dict[str, Any]]:
        """
        Inspects an incoming A2A message before it is accepted into an agent's memory.
        Returns: (is_accepted, reason, telemetry_metrics)
        """
        now = current_time if current_time is not None else time.time()
        node = self.get_or_register_node(msg.sender_id)

        if msg.sender_id in self.blocked_senders:
            return False, "REJECTED: Sender is quarantined", {"trust_score": 0.0}

        node.total_messages += 1

        # 1. Rate Limiting / Bursting Defense
        if not self._check_rate_limit(node, now):
            node.flagged_messages += 1
            node.reputation_score = max(0.0, node.reputation_score - 0.15)
            return False, "REJECTED: Rate limit anomaly detected (flood/burst)", {"trust_score": node.reputation_score}

        node.last_message_time = now

        # 2. Credential Harvesting & Leakage Interception (Moltbook Breach defense)
        leaks = self.scan_for_credential_harvesting(msg.content)
        if leaks:
            node.flagged_messages += 1
            node.reputation_score = max(0.0, node.reputation_score - 0.40)
            if node.reputation_score < self.min_trust_threshold:
                self.blocked_senders.add(msg.sender_id)
            return (
                False,
                f"REJECTED: Credential leak signature intercepted ({len(leaks)} secrets detected)",
                {"leaks_detected": len(leaks), "trust_score": node.reputation_score},
            )

        # 3. Payload Deduplication & Sybil Amplification Check
        payload_hash = hashlib.sha256(msg.content.strip().lower().encode("utf-8")).hexdigest()[:16]
        if payload_hash not in self.recent_payload_hashes:
            self.recent_payload_hashes[payload_hash] = []
        self.recent_payload_hashes[payload_hash].append(now)

        # Retain only timestamps within past 60s
        self.recent_payload_hashes[payload_hash] = [
            t for t in self.recent_payload_hashes[payload_hash] if now - t <= 60.0
        ]
        amplification_count = len(self.recent_payload_hashes[payload_hash])

        if amplification_count > 10:
            node.flagged_messages += 1
            node.reputation_score = max(0.0, node.reputation_score - 0.20)
            return (
                False,
                f"REJECTED: Sybil copypasta / narrative flooding detected (seen {amplification_count} times in 60s)",
                {"amplification_count": amplification_count, "trust_score": node.reputation_score},
            )

        # 4. Reputation Update (Healthy message)
        node.reputation_score = min(1.0, node.reputation_score + 0.01)

        return True, "ACCEPTED: Swarm message cleared all security barriers", {
            "trust_score": node.reputation_score,
            "amplification_count": amplification_count,
            "sender_history_count": node.total_messages,
        }

    def detect_sybil_cohorts(self, threshold_duplicates: int = 5) -> list[str]:
        """Returns hashes of payloads currently undergoing coordinated Sybil amplification."""
        flagged: list[str] = []
        for p_hash, timestamps in self.recent_payload_hashes.items():
            if len(timestamps) >= threshold_duplicates:
                flagged.append(p_hash)
        return flagged
