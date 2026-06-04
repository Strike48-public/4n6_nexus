"""Architectural guardrails enforced at the MCP tool boundary.

Every forensic tool invocation from every agent passes through ``ToolGuard.check``
before execution. Because agents have no other path to the tools, these controls
are *architectural* (structurally unavoidable), not prompt-based suggestions.

Three controls, all deny-by-default:

1. Per-tool argument allowlist -- a tool may only be called with flags it
   explicitly declares. Anything else (including any write/modify flag, however
   spelled) is rejected. This is strictly stronger than a write-flag denylist.
2. Evidence-path containment -- arguments that name input paths are canonicalised
   and must resolve inside the configured evidence root. Traversal escapes and
   absolute paths outside the root are rejected.
3. Circuit breaker -- N consecutive tool failures opens the boundary so a
   misbehaving loop cannot hammer the system.

See analysis/A2A_MESSAGE_SCHEMA.md (audit) and the Accuracy Report bypass-test
section, which exercises each rejection path above.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


class GuardrailViolation(Exception):
    """Raised when a tool invocation violates an architectural guardrail."""


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open due to consecutive failures."""


@dataclass(frozen=True)
class ToolPolicy:
    """Declares what a single tool is permitted to do (deny-by-default).

    Attributes:
        allowed_flags: The complete set of flags/positional tokens this tool may
            be invoked with. A bare token (not following a value flag) is permitted
            only if it is in this set (e.g. a whitelisted Volatility plugin name).
        path_flags: Flags whose following value is an INPUT path that must resolve
            inside the evidence root. Implies the flag consumes a value.
        value_flags: Flags that consume a following value which is NOT an evidence
            path (e.g. ``-r json`` format, ``--csv /out`` output dir). The value is
            consumed without allowlist-checking. ``path_flags`` are treated as
            value-consuming automatically; list only the non-path value flags here.
    """

    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    path_flags: frozenset[str] = field(default_factory=frozenset)
    value_flags: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        # Accept plain sets at construction for ergonomics; store as frozensets.
        object.__setattr__(self, "allowed_flags", frozenset(self.allowed_flags))
        object.__setattr__(self, "path_flags", frozenset(self.path_flags))
        # path flags always consume a value; fold them into value_flags.
        object.__setattr__(
            self,
            "value_flags",
            frozenset(self.value_flags) | frozenset(self.path_flags),
        )


class ToolGuard:
    """Enforces architectural guardrails at the MCP tool boundary."""

    def __init__(
        self,
        policies: dict[str, ToolPolicy],
        evidence_root: Path,
        max_consecutive_failures: int = 3,
    ):
        self.policies = policies
        self.evidence_root = Path(evidence_root).resolve()
        self.max_consecutive_failures = max_consecutive_failures
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None

    # -- circuit breaker -----------------------------------------------------

    def record_failure(self) -> None:
        self.failure_count += 1

    def record_success(self) -> None:
        self.failure_count = 0

    def reset_circuit(self) -> None:
        self.failure_count = 0
        self.last_failure_time = None

    @property
    def circuit_open(self) -> bool:
        return self.failure_count >= self.max_consecutive_failures

    # -- the boundary check --------------------------------------------------

    def check(self, tool: str, args: list[str]) -> None:
        """Validate a tool invocation. Raises on any violation; returns None if OK.

        Order: circuit breaker -> tool known -> per-arg allowlist -> path containment.
        """
        if self.circuit_open:
            raise CircuitBreakerOpen(
                f"Circuit breaker open: {self.failure_count} consecutive failures"
            )

        policy = self.policies.get(tool)
        if policy is None:
            raise GuardrailViolation(
                f"Tool '{tool}' is not on the allowlist (deny-by-default)"
            )

        self._check_args(tool, args, policy)

    def _check_args(self, tool: str, args: list[str], policy: ToolPolicy) -> None:
        """Walk args; every flag must be allowed, every path flag's value contained."""
        i = 0
        while i < len(args):
            token = args[i]

            if token.startswith("-"):
                if token not in policy.allowed_flags:
                    raise GuardrailViolation(
                        f"Flag '{token}' is not permitted for tool '{tool}' "
                        f"(allowed: {sorted(policy.allowed_flags)})"
                    )
                # Flags that consume a following value (paths, formats, output dirs).
                if token in policy.value_flags:
                    if i + 1 >= len(args):
                        raise GuardrailViolation(
                            f"Flag '{token}' for '{tool}' requires a value"
                        )
                    # Only input-path flags are containment-checked.
                    if token in policy.path_flags:
                        self._check_path_contained(args[i + 1])
                    i += 2
                    continue
                i += 1
                continue

            # A bare positional token: must be an explicitly allowed token
            # (e.g. a Volatility plugin name on the allowlist).
            if token not in policy.allowed_flags:
                raise GuardrailViolation(
                    f"Argument '{token}' is not permitted for tool '{tool}' "
                    f"(allowed: {sorted(policy.allowed_flags)})"
                )
            i += 1

    def _check_path_contained(self, raw_path: str) -> None:
        """Reject any input path that resolves outside the evidence root."""
        candidate = Path(raw_path).resolve()
        try:
            candidate.relative_to(self.evidence_root)
        except ValueError:
            raise GuardrailViolation(
                f"Path '{raw_path}' resolves outside the evidence root "
                f"'{self.evidence_root}' (read-only containment)"
            )
