"""
Attenuated Cryptographic Capability Tokens (Macaroons) for Zero-Trust Agents.

Eliminates raw ambient API tokens or root shell credentials. All agent operations
require cryptographically chained, unforgeable capability tokens bounded by
first-order logic caveats (TTL, target URI, exact action, max payload bytes).
"""

from __future__ import annotations
import dataclasses
import hashlib
import hmac
import json
import time
from typing import Any


@dataclasses.dataclass(frozen=True)
class MacaroonToken:
    """Cryptographic capability token with chained HMAC-SHA256 signature."""
    identifier: str
    caveats: tuple[str, ...]
    signature: str
    minted_at: float

    def to_json(self) -> str:
        return json.dumps({
            "identifier": self.identifier,
            "caveats": list(self.caveats),
            "signature": self.signature,
            "minted_at": self.minted_at,
        })

    @classmethod
    def from_json(cls, data_str: str) -> MacaroonToken:
        data = json.loads(data_str)
        return cls(
            identifier=data["identifier"],
            caveats=tuple(data["caveats"]),
            signature=data["signature"],
            minted_at=float(data["minted_at"]),
        )


def _compute_hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def mint_capability(
    root_key: bytes,
    identifier: str,
    caveats: list[str] | None = None,
    minted_at: float | None = None,
) -> MacaroonToken:
    """
    Mints a root capability token.
    Signature chain: Sig_0 = HMAC(root_key, identifier)
    For each caveat c_i: Sig_i = HMAC(Sig_{i-1}, c_i)
    """
    if caveats is None:
        caveats = []
    if minted_at is None:
        minted_at = time.time()

    current_sig = _compute_hmac(root_key, identifier)
    for c in caveats:
        current_sig = _compute_hmac(current_sig, c)

    return MacaroonToken(
        identifier=identifier,
        caveats=tuple(caveats),
        signature=current_sig.hex(),
        minted_at=minted_at,
    )


def attenuate(token: MacaroonToken, new_caveat: str) -> MacaroonToken:
    """
    Attenuates an existing token by appending a new first-order logic caveat.
    Anyone holding a token can attenuate it (further restrict it), but cannot broaden it.
    Sig_{n+1} = HMAC(Sig_n, new_caveat)
    """
    prior_sig = bytes.fromhex(token.signature)
    new_sig = _compute_hmac(prior_sig, new_caveat)
    updated_caveats = list(token.caveats) + [new_caveat]

    return MacaroonToken(
        identifier=token.identifier,
        caveats=tuple(updated_caveats),
        signature=new_sig.hex(),
        minted_at=token.minted_at,
    )


def verify_capability(
    root_key: bytes,
    token: MacaroonToken,
    context: dict[str, Any],
) -> tuple[bool, str]:
    """
    Verifies the cryptographic integrity of the token and checks all logic caveats
    against the current execution context.
    """
    # 1. Verify cryptographic HMAC chain
    current_sig = _compute_hmac(root_key, token.identifier)
    for c in token.caveats:
        current_sig = _compute_hmac(current_sig, c)

    if current_sig.hex() != token.signature:
        return False, "Invalid signature chain: token has been tampered with"

    # 2. Evaluate caveats against context
    current_time = context.get("current_time", time.time())

    for caveat in token.caveats:
        parts = [p.strip() for p in caveat.split()]
        if len(parts) < 3:
            return False, f"Malformed caveat syntax: {caveat}"

        var_name, op, val_str = parts[0], parts[1], " ".join(parts[2:])

        if var_name == "time_valid_until":
            try:
                deadline = float(val_str)
                if current_time > deadline:
                    return False, f"Token expired: current_time ({current_time}) > deadline ({deadline})"
            except ValueError:
                return False, f"Invalid timestamp in caveat: {val_str}"

        elif var_name == "action":
            req_action = context.get("action")
            if op == "==" and req_action != val_str:
                return False, f"Action mismatch: required {val_str}, got {req_action}"
            elif op == "!=" and req_action == val_str:
                return False, f"Disallowed action: {req_action}"

        elif var_name == "target_uri":
            req_uri = context.get("target_uri", "")
            if op == "==" and req_uri != val_str:
                return False, f"URI mismatch: expected {val_str}, got {req_uri}"
            elif op == "prefix" and not req_uri.startswith(val_str):
                return False, f"URI prefix mismatch: {req_uri} does not start with {val_str}"

        elif var_name == "max_payload_bytes":
            try:
                max_bytes = int(val_str)
                actual_bytes = context.get("payload_bytes", 0)
                if actual_bytes > max_bytes:
                    return False, f"Payload limit exceeded: {actual_bytes} bytes > {max_bytes}"
            except ValueError:
                return False, f"Invalid byte limit: {val_str}"

        elif var_name == "read_only":
            if val_str.lower() in ("true", "1") and context.get("is_mutation", False):
                return False, "Mutation disallowed by read_only caveat"

    return True, "Capability verified and all caveats satisfied"
