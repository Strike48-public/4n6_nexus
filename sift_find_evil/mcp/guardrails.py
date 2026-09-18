"""Architectural guardrails enforced at the MCP tool boundary.

Every forensic tool invocation from every agent passes through ``ToolGuard.check``
before execution. Because agents have no other path to the tools, these controls
are *architectural* (structurally unavoidable), not prompt-based suggestions.

Four controls, all deny-by-default:

1. Per-tool argument allowlist -- a tool may only be called with flags it
   explicitly declares. Anything else (including any write/modify flag, however
   spelled) is rejected. This is strictly stronger than a write-flag denylist.
2. Evidence-path containment -- arguments that name input paths are canonicalised
   and must resolve inside the configured evidence root. Traversal escapes and
   absolute paths outside the root are rejected. Its inverse (SFE-fibx.2): an
   OUTPUT-writing flag (a policy's ``output_flags``, e.g. ``--csv <dir>``) must
   resolve OUTSIDE the evidence root, so the boundary cannot be told to write into
   read-only evidence.

   SCOPING NOTE -- INPUT-path containment is SURGICAL, not heuristic: an input
   path is checked against the single ``evidence_root`` this guard was constructed
   with (the MCP server's configured case directory). Unlike the CLI's
   ``_resolves_into_evidence_dir``, it does NOT also blanket-block
   ``/cases``/``/mnt``/``/media`` for input, because an MCP server serves one case
   at a time. OUTPUT containment is deliberately WIDER (SFE-fibx.15): an output
   path is rejected if it resolves inside ``evidence_root`` OR carries any
   ``evidence`` path component. This is the CLI guard's second clause (the
   ``evidence``-component check) but NOT its ``/cases``/``/mnt``/``/media`` prefix
   clause -- so a legitimate sibling output dir like ``/cases/INC-.../analysis``
   still passes, while writing into ANOTHER case's evidence subtree
   (``/cases/caseB/evidence/out`` while ``evidence_root`` is ``/tmp/caseA``) is
   refused. That closes the dev/multi-case cross-contamination risk that a
   root-only check would miss. ``evidence_root`` should still be set to the actual
   case evidence location, and a case's output dir must not be named ``evidence``.
3. Circuit breaker -- N consecutive tool failures opens the boundary so a
   misbehaving loop cannot hammer the system.
4. Role-scoped tool authorization (SFE-l7mp) -- each tool is tagged with the
   analyst roles permitted to call it; a call whose caller-role is not on the
   tool's role set is rejected. This governs *who* may run a tool, orthogonal to
   the arg allowlist's *how*. Enforcement is opt-in: a call with no role is
   subject only to controls 1-3, so the boundary stays backward-compatible.

   NOTE on strength: unlike controls 1-3, which constrain caller-supplied ARGS
   against a fixed policy the caller cannot alter, the role is a *caller-supplied
   tag* (the ``agent`` identity). A caller that controls that field can name its
   owning role and pass. So control 4 is DEFENSE-IN-DEPTH + audit clarity (it
   stops an analyst from straying outside its remit and records the attempt on
   the correlated thread), NOT an authentication boundary. Binding the role to a
   trusted transport/session identity would make it one; today it is not.

See analysis/A2A_MESSAGE_SCHEMA.md (audit) and the Accuracy Report bypass-test
section, which exercises each rejection path above.
"""

from __future__ import annotations

import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


class GuardrailViolation(Exception):
    """Raised when a tool invocation violates an architectural guardrail."""


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open due to consecutive failures."""


# Tool key -> the executable actually on PATH. The guardrail, the audit log, and
# every wrapper key a tool by its logical name; the exec boundary must translate
# that key to the real binary. Only tools whose executable differs from their key
# appear here -- everything else is an identity map (see ``tool_binary``).
#
# ``volatility``: Volatility 3 installs its CLI as ``vol`` (see
# memory/volatility_runner.py and Dockerfile.connector-gui), NOT ``volatility``.
# Keying the policy/audit as ``volatility`` while execing ``vol`` keeps the
# logical name stable across the audit trail and the advertised capability.
#
# ``sleuthkit``: The Sleuth Kit ships no ``sleuthkit`` binary -- it is a suite
# (fls/icat/mmls/mactime). The ``sleuthkit`` key is a policy DOMAIN; the exposed
# capability is a read-only file listing, which is ``fls`` (SFE-qdlk).
TOOL_BINARIES: dict[str, str] = {
    "volatility": "vol",
    "sleuthkit": "fls",
}


def tool_binary(tool: str) -> str:
    """Resolve a logical tool key to the executable to spawn (identity default)."""
    return TOOL_BINARIES.get(tool, tool)


# Tool key -> the ``platform.system()`` values on which the tool can actually do
# work. A resolvable binary is NOT the same as a runnable tool, so the which()
# probe alone over-advertises (SFE-ybki, same class as SFE-wnr4/SFE-qdlk).
#
# ``pecmd``: PECmd needs Windows-only decompression libraries. On Linux the
# bare-name wrapper (docker/install-eztools.sh) dispatches through .NET and the
# binary resolves, but PECmd prints "Non-Windows platforms not supported due to
# the need to load decompression specific Windows libraries! Exiting..." and does
# no work -- while EXITING 0. Because the exec boundary scores success as
# ``returncode == 0``, an unguarded call reported success for a run that produced
# no Prefetch CSV: a silent failure, not a visibly missing tool. The other three
# EZ Tools (MFTECmd/EvtxECmd/RECmd) are cross-platform and stay ungated.
#
# Deliberately a DENYLIST keyed by tool: an entry here is a positive claim that a
# tool cannot work somewhere. An unlisted tool is runnable everywhere, so adding
# a tool never silently disables it.
TOOL_PLATFORMS: dict[str, frozenset[str]] = {
    "pecmd": frozenset({"Windows"}),
}


def tool_supported_on_platform(
    tool: str, system: Optional[Callable[[], str]] = None
) -> bool:
    """Whether ``tool`` can do real work on this platform.

    Consulted at BOTH doorways -- the advertised capability set and the exec
    boundary -- so a tool cannot be offered where it cannot run, and a caller
    naming it directly still gets an explicit refusal instead of a hollow
    success. ``system`` is injected so tests are deterministic rather than
    dependent on the host OS.

    ``system`` defaults to None and resolves ``platform.system`` at CALL time
    rather than binding it as a default argument: a default is bound once at
    definition, which would make the live platform unpatchable and silently
    pin every no-argument caller (the exec doorway) to import-time state.
    """
    required = TOOL_PLATFORMS.get(tool)
    if required is None:
        return True
    current = system() if system is not None else platform.system()
    return current in required


# -- role-scoped tool authorization (SFE-l7mp) -------------------------------
#
# Least-privilege on TOP of the per-arg allowlist: the arg allowlist governs
# *how* a tool runs; this governs *who* may run it. Each analyst role maps to
# the tools it may call, keyed by the same logical tool name the policy/audit
# use. Grounded in the live DFIR roster (.claude/agents/dfir-*) and the per-tool
# ``agent`` defaults in server.build_fastmcp:
#
#   disk_analyst    -- Windows disk artifacts + Sleuth Kit file listing
#   memory_analyst  -- Volatility 3 memory plugins
#   network_analyst -- tshark PCAP field extraction
#   verifier        -- READ-ONLY TIEBREAKER set only (SFE-l7mp operator decision
#                      2026-08-12): the narrow lookups the self_correction loop
#                      re-runs to resolve a contradiction (psscan via volatility,
#                      Event Log 4688 via evtxecmd). NOT the blanket "no forensic
#                      tools" the gallery states, because our dfir-verifier
#                      resolves contradictions with a live tiebreaker tool call.
#                      It may not list disk images or run unrelated tools.
#   orchestrator /  -- run NO forensic tool directly (empty set). This mirrors
#   lead / triage      the live agent defs (dfir-orchestrator exposes only
#                      Read/Grep/Glob/Agent -- no forensics_nexus tools): these
#                      roles DISPATCH analysts, they do not execute tools. The
#                      gate keys on the forensic tool being run, so a job's
#                      poll/load (which never re-run a tool) is unaffected -- only
#                      an attempt to run/stage a forensic tool under a dispatch
#                      role is refused.
#
# Deny-by-default: a role absent from this map, or a tool absent from a role's
# set, authorizes nothing. The dispatch roles are listed with an explicit empty
# set to document that "runs no forensic tool" is intentional, not an omission.
# Built as a module-level literal so a role's reach is auditable at import time
# and cannot drift from the exposed tool set (a test asserts every forensic tool
# with a default policy is reachable by at least one role).
ROLE_ACCESS: dict[str, frozenset[str]] = {
    "disk_analyst": frozenset({"mftecmd", "pecmd", "evtxecmd", "recmd", "sleuthkit"}),
    "memory_analyst": frozenset({"volatility"}),
    "network_analyst": frozenset({"tshark"}),
    "verifier": frozenset({"volatility", "evtxecmd"}),
    "orchestrator": frozenset(),
    "lead": frozenset(),
    "triage": frozenset(),
}


# Dispatch roles run no forensic tool directly, but their JOB is to dispatch and
# manage work for the analysts -- so they may stage/manage detached jobs for any
# tool (the payload's args stay hard-guarded at staging regardless). They are the
# roles in ROLE_ACCESS whose tool set is empty. Kept as its own predicate so the
# job-control path can distinguish "manages the queue" from "runs the tool".
DISPATCH_ROLES: frozenset[str] = frozenset(
    role for role, tools in ROLE_ACCESS.items() if not tools
)


# The universe of tools any role claims. The role gate applies ONLY to tools in
# this set: a tool no role governs (a bespoke/test tool) is outside the role
# dimension and falls through to the arg allowlist. Every REAL forensic tool is
# here -- test_registry_covers_every_forensic_tool asserts every default-policy
# tool is role-reachable, so a new forensic tool that forgets its role entry
# fails CI rather than shipping role-unprotected.
ROLE_GOVERNED_TOOLS: frozenset[str] = frozenset().union(*ROLE_ACCESS.values())


def get_tools_for_role(role: str) -> set[str]:
    """Return the set of tools ``role`` may call (empty for an unknown role)."""
    return set(ROLE_ACCESS.get(role, frozenset()))


def is_dispatch_role(role: Optional[str]) -> bool:
    """True iff ``role`` is a dispatch/management role (owns no forensic tool).

    Match is case-insensitive to mirror ``ToolGuard.check``'s role normalization.
    """
    return role is not None and role.strip().lower() in DISPATCH_ROLES


def role_can_use(role: str, tool: str) -> bool:
    """True iff ``role`` is authorized to call ``tool`` (deny-by-default)."""
    return tool in ROLE_ACCESS.get(role, frozenset())


def is_role_governed(tool: str) -> bool:
    """True iff at least one role claims ``tool`` (so the role gate applies)."""
    return tool in ROLE_GOVERNED_TOOLS


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
        positional_path: When True, a bare positional token that is NOT on
            ``allowed_flags`` is treated as an INPUT evidence path and
            containment-checked (rather than rejected). This is for tools that
            take their evidence target positionally, with no flag -- e.g.
            ``fls -r -o <offset> <image>`` (SFE-qdlk). Default False, so a tool
            that never opts in keeps rejecting unknown positionals as before.
        output_flags: Flags whose following value is an OUTPUT directory the tool
            WRITES to (e.g. EZTools ``--csv <dir>``). The value is containment-
            checked with the INVERSE of path_flags: it must NOT resolve inside the
            evidence root, so the boundary cannot be told to write into read-only
            evidence (SFE-fibx.2). Implies the flag consumes a value. An output
            flag is the only write-shaped flag a read-only policy may permit, and
            only because its target is provably outside evidence.
    """

    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    path_flags: frozenset[str] = field(default_factory=frozenset)
    value_flags: frozenset[str] = field(default_factory=frozenset)
    positional_path: bool = False
    output_flags: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        # Accept plain sets at construction for ergonomics; store as frozensets.
        object.__setattr__(self, "allowed_flags", frozenset(self.allowed_flags))
        object.__setattr__(self, "path_flags", frozenset(self.path_flags))
        object.__setattr__(self, "output_flags", frozenset(self.output_flags))
        # A flag is an INPUT-path flag (must resolve inside evidence) XOR an
        # OUTPUT flag (must resolve outside it) -- never both. If it were listed
        # as both, ``_check_args``'s ``if path_flags / elif output_flags`` would
        # silently resolve it as an input path and the output containment check
        # would never run: a latent footgun. Fail loudly at construction instead
        # (SFE-fibx.15). Unreachable in default_policies today; this keeps it so.
        overlap = self.path_flags & self.output_flags
        if overlap:
            raise ValueError(
                f"ToolPolicy flags must be disjoint: {sorted(overlap)} listed as "
                "both path_flags (input) and output_flags (output)"
            )
        # path flags AND output flags always consume a value; fold both into
        # value_flags so the arg walker skips their value token.
        object.__setattr__(
            self,
            "value_flags",
            frozenset(self.value_flags)
            | frozenset(self.path_flags)
            | frozenset(self.output_flags),
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

    def check(self, tool: str, args: list[str], role: Optional[str] = None) -> None:
        """Validate a tool invocation. Raises on any violation; returns None if OK.

        Order: circuit breaker -> tool known -> role authorization -> per-arg
        allowlist -> path containment.

        Args:
            tool: logical tool name (keys the policy and the role registry).
            args: the tool argument vector.
            role: the caller's analyst role (SFE-l7mp). When ``None`` the role
                gate is skipped and only controls 1-3 apply -- so an existing
                caller that supplies no role behaves exactly as before. When a
                role IS supplied it must be authorized for ``tool`` in
                ``ROLE_ACCESS`` (deny-by-default), else ``GuardrailViolation``.
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

        # Role authorization is opt-in: enforced only when a caller identifies a
        # role AND the tool is one some role governs. A tool no role claims is
        # outside the role dimension and defers to the arg allowlist (so a
        # bespoke tool with its own policy is unaffected). A disallowed
        # (role, governed-tool) pair is refused before the arg check.
        #
        # Role match is normalized (strip + lowercase): the registry keys are
        # canonical lowercase, so a caller that supplies ``Memory_Analyst`` or a
        # space-padded id still resolves rather than being denied for a cosmetic
        # mismatch. (Fail-closed either way -- an unrecognised role authorizes
        # nothing.)
        if role is not None:
            role = role.strip().lower()
        if role is not None and is_role_governed(tool) and not role_can_use(role, tool):
            raise GuardrailViolation(
                f"Role '{role}' is not authorized to call tool '{tool}' "
                f"(role-scoped allowlist: {sorted(get_tools_for_role(role))})"
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
                    # Input-path flags must resolve INSIDE evidence; output
                    # flags must resolve OUTSIDE it (never write into read-only
                    # evidence). A flag is never both.
                    if token in policy.path_flags:
                        self._check_path_contained(args[i + 1])
                    elif token in policy.output_flags:
                        self._check_output_not_in_evidence(args[i + 1])
                    i += 2
                    continue
                i += 1
                continue

            # A bare positional token that IS on the allowlist (e.g. a Volatility
            # plugin name) is permitted as-is.
            if token in policy.allowed_flags:
                i += 1
                continue

            # An unknown positional: for a positional_path tool it is the input
            # evidence target -- containment-check it (e.g. the `fls ... <image>`
            # positional). Otherwise it is not permitted (deny-by-default).
            if policy.positional_path:
                self._check_path_contained(token)
                i += 1
                continue

            raise GuardrailViolation(
                f"Argument '{token}' is not permitted for tool '{tool}' "
                f"(allowed: {sorted(policy.allowed_flags)})"
            )

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

    def _check_output_not_in_evidence(self, raw_path: str) -> None:
        """Reject an output path that resolves INSIDE the evidence root.

        The inverse of :meth:`_check_path_contained`: an output-writing flag
        (e.g. ``--csv <dir>``) must never target the read-only evidence tree, or
        the tool could be told to write into the very artifacts it is analyzing.
        Resolves symlinks/relative parts first so a symlink into evidence is
        caught. ``strict`` is implicit in ``resolve`` (a not-yet-created output
        dir still resolves against its real parent).

        Beyond the single configured ``evidence_root``, ALSO reject any path with
        an ``evidence`` path component (mirrors the CLI's second clause,
        cli._resolves_into_evidence_dir). This closes the dev/multi-case risk of
        writing into ANOTHER case's evidence subtree -- e.g. ``--csv`` into
        ``/cases/caseB/evidence/out`` while ``evidence_root`` is ``/tmp/caseA``.
        It does NOT bring the CLI's ``/cases,/mnt,/media`` prefix clause across,
        which would false-positive a legitimate ``/cases/INC-.../analysis`` output
        dir (SFE-fibx.15).
        """
        candidate = Path(raw_path).resolve()
        in_configured_root = (
            candidate == self.evidence_root
            or candidate.is_relative_to(self.evidence_root)
        )
        in_any_evidence_dir = any(part == "evidence" for part in candidate.parts)
        if in_configured_root or in_any_evidence_dir:
            raise GuardrailViolation(
                f"Output path '{raw_path}' resolves inside an evidence directory "
                f"(configured root '{self.evidence_root}' or an 'evidence' path "
                "component) -- refusing to write into read-only evidence (route "
                "output to a non-evidence directory)"
            )
