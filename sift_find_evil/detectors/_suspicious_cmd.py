"""Shared suspicious-command table for the Linux detectors.

A single offensive-command shape table, reused by every Linux surface that
inspects a command string -- systemd ``ExecStart``, cron lines, shell-init
lines (``LinuxPersistenceDetector``) and recorded shell history
(``LinuxExecutionDetector``). Keeping one table means "a suspicious command"
means the same thing on every surface and cannot drift between detectors.

Each pattern captures a distinct offensive shape a defender expects in a
malicious payload. Patterns are compiled case-insensitively and matched against
the raw command text.

**One surface-dependent shape: /tmp and /dev/shm (SFE-l3ep).** These
world-writable directories mean different things in different positions:

- On a **persistence directive** (a systemd ``ExecStart``, a cron line, a
  shell-init line) the whole command *is* an execution directive, so *any*
  reference to a world-writable path is inherently suspicious -- the attacker
  has arranged for boot/scheduled/login code to touch ``/tmp``.
- On **interactive shell history** the same reference is far noisier: a real
  operator constantly reads and edits files there (``cat /tmp/report``,
  ``vim /tmp/notes``, ``ls -la /tmp/``). There the reference is offensive only
  in an *execution or staging* position -- run as a program, interpreted by a
  shell, made executable, or written into by a downloader.

So callers pick the shape via :func:`match_suspicious`'s ``interactive`` flag.
Every other shape is context-free. The path fragment (:data:`_WW`) is defined
once and shared by both variants, so the two cannot drift on *what* counts as a
world-writable path -- only on *where in the command* it must appear.
"""

from __future__ import annotations

import re
from typing import Optional

# A path under a world-writable staging directory (single source for both /tmp
# shape variants below).
_WW = r"(?:/tmp/|/dev/shm/)"

# Shapes that mean the same thing on every surface -- the command text alone is
# unambiguously offensive regardless of interactive vs. directive context.
_BASE_SHAPES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bbash\s+-i\b", re.IGNORECASE),
        "interactive bash reverse shell (bash -i)",
    ),
    (re.compile(r"/dev/tcp/", re.IGNORECASE), "bash /dev/tcp network redirection"),
    (
        re.compile(r"\bnc\b[^\n]*\s-e\b", re.IGNORECASE),
        "netcat with -e command execution",
    ),
    (
        re.compile(r"\bncat\b[^\n]*\s-e\b", re.IGNORECASE),
        "ncat with -e command execution",
    ),
    (re.compile(r"base64\s+(?:-d|--decode)", re.IGNORECASE), "base64-decoded payload"),
    (re.compile(r"\beval\b", re.IGNORECASE), "eval of dynamic content"),
    (
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
        "curl/wget piped to a shell",
    ),
)

# /tmp shape for persistence directives: any reference to a world-writable path
# in a boot/scheduled/login directive is suspicious.
_TMP_DIRECTIVE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"{_WW}\S*", re.IGNORECASE), "execution from /tmp or /dev/shm"),
)

# /tmp shape for interactive history: only an execution or staging position
# fires, so a benign read/navigation reference does not false-positive. All
# three share one reason so "a suspicious /tmp command" still means one thing.
_TMP_INTERACTIVE_REASON = "execution or staging under /tmp or /dev/shm"
_TMP_INTERACTIVE: tuple[tuple[re.Pattern[str], str], ...] = (
    # (a) executable position: the world-writable path is the program being run
    # -- at line start or after a command separator (| ; & ` $(), optionally via
    # a launcher (sudo/exec/nohup/command) and/or a wrapping quote. Matches
    # ``/tmp/x``, ``sudo /tmp/x``, ``'/tmp/x'``, ``foo | /dev/shm/x``; not
    # ``cat /tmp/x`` (cat, not the path, is the verb).
    (
        re.compile(
            rf"(?:^|[|;&`]|\$\()\s*(?:(?:sudo|exec|nohup|command)\s+)*[\"']?{_WW}\S*",
            re.IGNORECASE,
        ),
        _TMP_INTERACTIVE_REASON,
    ),
    # (b) interpreted: a shell or scripting interpreter (or ``source``) runs a
    # world-writable path. Matches ``bash /tmp/x.sh``, ``source /dev/shm/x``,
    # ``python3 /tmp/x.py``, ``perl /tmp/x.pl``.
    (
        re.compile(
            rf"\b(?:bash|sh|dash|zsh|ksh|source|python[0-9.]*|perl|ruby|php)\s+"
            rf"(?:-\S+\s+)*[\"']?{_WW}",
            re.IGNORECASE,
        ),
        _TMP_INTERACTIVE_REASON,
    ),
    # (c) made-executable: ``chmod`` arms a world-writable path for execution --
    # either ``+x`` (any principal: ``+x``, ``u+x``, ``a+x``) or a numeric octal
    # mode whose owner/group/other triad sets an execute bit (an odd digit,
    # 1/3/5/7). Matches ``chmod +x /tmp/x``, ``chmod 755 /tmp/x``; not
    # ``chmod 644 /tmp/x`` (no execute bit).
    (
        re.compile(
            rf"\bchmod\b[^|;&`\n]*\+x[^|;&`\n]*{_WW}"
            rf"|\bchmod\s+(?:-\S+\s+)*[0-7]*[1357][0-7]*\b[^|;&`\n]*{_WW}",
            re.IGNORECASE,
        ),
        _TMP_INTERACTIVE_REASON,
    ),
    # (d) download staging: a downloader writes a payload into a world-writable
    # path. The path must follow whitespace or ``=`` (then an optional quote) so
    # a URL containing ``/tmp/`` (e.g. ``curl https://host/tmp/page``) does not
    # match. Matches ``wget URL -O /tmp/implant``, ``curl -o "/tmp/x" URL``.
    (
        re.compile(rf"\b(?:curl|wget)\b[^|;&`\n]*[\s=][\"']?{_WW}", re.IGNORECASE),
        _TMP_INTERACTIVE_REASON,
    ),
)


def match_suspicious(command: str, *, interactive: bool = False) -> Optional[str]:
    """Return the reason string for the first suspicious pattern that matches.

    Args:
        command: Raw command text to test.
        interactive: ``True`` when ``command`` came from an interactive shell
            history line, ``False`` (default) when it is a persistence directive
            (systemd ``ExecStart``, cron line, shell-init line). Only the /tmp
            and /dev/shm shape differs: a directive treats any world-writable
            path as suspicious, while interactive history requires an execution
            or staging position (see module docstring, SFE-l3ep).

    Returns:
        The human-readable reason for the first matching pattern, or ``None``
        when the command matches nothing.
    """
    tmp_shapes = _TMP_INTERACTIVE if interactive else _TMP_DIRECTIVE
    for pattern, reason in (*_BASE_SHAPES, *tmp_shapes):
        if pattern.search(command):
            return reason
    return None
