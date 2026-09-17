"""MFTECmd/EvtxECmd/RECmd actually RUN on Linux, not just exit 0 (SFE-7foj).

SFE-ybki (#208) closed PECmd's silent Linux failure: it prints "Non-Windows
platforms not supported ... Exiting" and exits 0 WITHOUT doing any work, and the
exec doorways scored ``returncode == 0`` as success. The other three routed EZ
Tools are believed cross-platform -- verified empirically during that PR, but no
automated test asserted they produce REAL output rather than merely resolving and
exiting 0, which is exactly the property that fooled us for PECmd.

This suite pins it: each of the three MUST print its real engine banner
("<Tool> version ...") and MUST NOT emit PECmd's platform-refusal marker. The
same check applied to PECmd MUST fail (``test_the_check_discriminates_pecmd``),
so the assertion genuinely guards a regression rather than rubber-stamping any
exit-0 banner.

Defense-in-depth, NOT a live defect: the advertise gate (TOOL_PLATFORMS in
``sift_find_evil.mcp.guardrails``) already stops an unrunnable tool from being
offered. This guards a DIRECT exec -- Matrix Mode A routing or
``EZToolsTool(...).mftecmd()`` -- against a future .NET/library regression.

CI scope (honest): the required ``core``/``forensic`` jobs install no .NET, so
these tests SKIP there. The load-bearing CI enforcement of the same property runs
in ``.github/workflows/connector-image.yml`` (the eztools smoke, which has .NET).
These tests execute on the connector image / any dev host / SIFT with EZ Tools
installed, and self-verify the discriminator regardless of platform.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from sift_find_evil.mcp.guardrails import TOOL_PLATFORMS

pytestmark = pytest.mark.integration

# Tools that must actually run on Linux (NOT gated in TOOL_PLATFORMS).
_CROSS_PLATFORM_TOOLS = ("mftecmd", "evtxecmd", "recmd")

# PECmd's documented Linux refusal marker (the exact text SFE-ybki keyed on).
_REFUSAL = re.compile(r"not supported|Non-Windows platforms", re.IGNORECASE)


def _run_bare(tool: str) -> str:
    """Run a tool with no args and return combined stdout+stderr.

    A bare invocation is enough to tell a running engine from a platform refusal:
    a cross-platform EZ tool prints its "<Tool> version ..." banner; PECmd prints
    only its refusal and exits without a banner. ``check=False`` because a bare
    banner exits nonzero -- the return code is not the signal here, the OUTPUT is
    (the same reason SFE-ybki could not trust ``returncode == 0``).
    """
    proc = subprocess.run(
        [tool],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.stdout + proc.stderr


def _runs_on_linux(tool: str) -> bool:
    """True iff ``tool`` actually entered its engine (banner + not the refusal)."""
    out = _run_bare(tool)
    if _REFUSAL.search(out):
        return False
    # Banner is tool-specific ("MFTECmd version", "RECmd version", ...), matched
    # case-insensitively, so a stray "version" from an unrelated line cannot pass.
    return re.search(rf"{re.escape(tool)} version", out, re.IGNORECASE) is not None


@pytest.mark.parametrize("tool", _CROSS_PLATFORM_TOOLS)
def test_cross_platform_eztool_produces_real_output_on_linux(tool: str) -> None:
    """Each cross-platform EZ tool runs for real on Linux -- not a silent no-op."""
    if shutil.which(tool) is None or shutil.which("dotnet") is None:
        pytest.skip(
            f"{tool} or dotnet not installed (see connector-image eztools smoke)"
        )
    assert tool not in TOOL_PLATFORMS, (
        f"{tool} is gated in TOOL_PLATFORMS but this test assumes it is "
        "cross-platform -- reconcile the two."
    )
    assert _runs_on_linux(tool), (
        f"{tool} did not produce real output on Linux (no engine banner, or it "
        f"refused like PECmd). If it genuinely cannot run here, add it to "
        f"TOOL_PLATFORMS in sift_find_evil/mcp/guardrails.py alongside pecmd."
    )


def test_the_check_discriminates_pecmd() -> None:
    """The discriminator is meaningful: PECmd -- the one tool that refuses on
    Linux -- MUST fail ``_runs_on_linux``. If this ever passes, the check has
    degraded to a rubber stamp (it would then green a regressed cross-platform
    tool too), so guard it here rather than trusting the positive tests alone."""
    if shutil.which("pecmd") is None:
        pytest.skip("pecmd not installed")
    assert "pecmd" in TOOL_PLATFORMS, "pecmd should be platform-gated (SFE-ybki)"
    assert not _runs_on_linux(
        "pecmd"
    ), "pecmd unexpectedly looks functional on Linux -- re-check TOOL_PLATFORMS"
