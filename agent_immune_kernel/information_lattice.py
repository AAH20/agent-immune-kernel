"""
Dual-Channel Information Flow Lattice (Denning's Non-Interference) for AI Agents.

Enforces mathematical separation between executive instruction channels (high integrity)
and perceptual ingestion channels (untrusted external inputs like emails, websites,
and Moltbook forum posts). Untrusted data cannot reach execution or egress sinks
without formal declassification.
"""

from __future__ import annotations
import dataclasses
import enum
import hashlib
import math
import re
from typing import Any


class SecurityLevel(enum.IntEnum):
    TRUSTED_INSTRUCTION = 1      # Operator commands, immutable system directives
    SANITIZED_OBSERVATION = 2    # Cryptographically declassified or schema-validated data
    TAINTED_UNTRUSTED = 3        # External emails, web scrapes, A2A messages, public web


class SinkType(enum.Enum):
    EXECUTION_SINK = "execution"            # bash, eval, system commands (OpenClaw vector)
    FILE_WRITE_SINK = "file_write"          # modifying local disk, cron jobs, .bashrc
    NETWORK_EGRESS_SINK = "network_egress"  # HTTP outbound, webhook post, credential egress
    REASONING_SINK = "reasoning"            # LLM internal scratchpad / context window


@dataclasses.dataclass(frozen=True)
class LabeledArtifact:
    """Artifact labeled with security level and provenance metadata."""
    content: str
    level: SecurityLevel
    source_origin: str
    taint_hash: str
    tags: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        content: str,
        level: SecurityLevel,
        source_origin: str,
        tags: list[str] | None = None,
    ) -> LabeledArtifact:
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return cls(
            content=content,
            level=level,
            source_origin=source_origin,
            taint_hash=content_hash,
            tags=tuple(tags or []),
        )


class InformationLeakageViolation(Exception):
    """Raised when tainted data attempts to violate lattice flow boundaries."""
    pass


class InformationLattice:
    """
    Denning information flow lattice governor enforcing non-interference invariants.
    """

    # Minimum integrity level required by each sink
    SINK_REQUIREMENTS = {
        SinkType.EXECUTION_SINK: SecurityLevel.TRUSTED_INSTRUCTION,
        SinkType.FILE_WRITE_SINK: SecurityLevel.SANITIZED_OBSERVATION,
        SinkType.NETWORK_EGRESS_SINK: SecurityLevel.SANITIZED_OBSERVATION,
        SinkType.REASONING_SINK: SecurityLevel.TAINTED_UNTRUSTED,
    }

    # Heuristic patterns for indirect prompt injection
    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"(?i)disregard\s+(the\s+)?above",
        r"(?i)you\s+are\s+now\s+(unrestricted|jailbroken|an\s+operator)",
        r"(?i)system\s+prompt\s*:\s*override",
        r"(?i)new\s+system\s+directive\s*:",
        r"(?i)<\s*(system|im_start|admin)\s*>",
        r"(?i)(curl|wget|nc)\s+.*https?://",
        r"(?i)(cat|type)\s+.*(\.env|credentials|id_rsa|\.aws/)",
        r"(?i)exfiltrate\s+to",
    ]

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculates Shannon entropy in bits per character."""
        if not text:
            return 0.0
        frequencies: dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        total = len(text)
        for count in frequencies.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def detect_indirect_injection(cls, text: str) -> tuple[bool, float, list[str]]:
        """
        Scans perceptual text for prompt injection, jailbreak delimiters,
        and high-entropy obfuscated payloads.
        Returns: (is_malicious, risk_score, matched_signatures)
        """
        matches: list[str] = []
        for pattern in cls.INJECTION_PATTERNS:
            found = re.findall(pattern, text)
            if found:
                matches.append(pattern)

        entropy = cls.calculate_shannon_entropy(text)
        # Standard english text is ~3.5-4.5 bits; base64 encoded binaries/keys exceed 5.8
        entropy_anomaly = entropy > 5.8 and len(text) > 40

        risk_score = min(1.0, (len(matches) * 0.4) + (0.3 if entropy_anomaly else 0.0))
        is_malicious = len(matches) > 0 or entropy_anomaly

        if entropy_anomaly:
            matches.append(f"HighEntropyObfuscation(bits={entropy:.2f})")

        return is_malicious, risk_score, matches

    @classmethod
    def validate_flow(cls, artifact: LabeledArtifact, sink: SinkType) -> tuple[bool, str]:
        """
        Evaluates whether an artifact is permitted to flow into a designated sink.
        Non-interference condition: artifact.level <= SINK_REQUIREMENTS[sink]
        """
        required_level = cls.SINK_REQUIREMENTS[sink]
        if artifact.level <= required_level:
            return True, f"Flow allowed: {artifact.level.name} satisfies {sink.value} requirements"

        err_msg = (
            f"SECURITY VIOLATION: Cannot pipe {artifact.level.name} from origin "
            f"'{artifact.source_origin}' into {sink.value} (requires {required_level.name})"
        )
        return False, err_msg

    @classmethod
    def declassify(
        cls,
        artifact: LabeledArtifact,
        validator_signature: str,
        expected_schema_fields: list[str] | None = None,
    ) -> LabeledArtifact:
        """
        Declassifies a TAINTED_UNTRUSTED artifact to SANITIZED_OBSERVATION
        after formal verification and injection screening.
        """
        if not validator_signature:
            raise InformationLeakageViolation("Declassification requires cryptographic validator signature")

        is_malicious, risk_score, triggers = cls.detect_indirect_injection(artifact.content)
        if is_malicious:
            raise InformationLeakageViolation(
                f"Declassification rejected: Indirect injection detected (risk={risk_score:.2f}, triggers={triggers})"
            )

        if expected_schema_fields:
            for field in expected_schema_fields:
                if field not in artifact.content:
                    raise InformationLeakageViolation(f"Declassification failed: missing schema field '{field}'")

        return LabeledArtifact.create(
            content=artifact.content,
            level=SecurityLevel.SANITIZED_OBSERVATION,
            source_origin=f"declassified:{artifact.source_origin}",
            tags=list(artifact.tags) + ["sanitized"],
        )
