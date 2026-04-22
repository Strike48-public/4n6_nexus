# T1140 Real-World Validation

Validation of `sift_find_evil.memory.obfuscation.analyze_cmdline_obfuscation`
against a realistic Windows cmdline corpus (SFE-3co follow-up).

## Corpus

- **Benign (24)** — admin cmdlines sampled from a clean Win10 box:
  svchost/services, `WmiPrvSE -Embedding`, `certutil -hashfile`,
  `certutil -store my`, `bitsadmin /list`, local `regsvr32 /s`,
  local `mshta` HTA launch, `rundll32` shell32/printui, PowerShell
  with embedded base64 that is not `-EncodedCommand`, GPO wrappers,
  Chocolatey/winget, Edge/Chrome launch lines with long flag
  switches, and a `curl` with a JWT-looking `Authorization: Bearer`
  token (the worst shape for false-positive base64 matching).

- **Malicious (10)** — known-bad patterns from public IR / MITRE:
  PowerShell `-EncodedCommand` download cradle, `-enc` short alias,
  squiblydoo (`rundll32 javascript:`), squiblytwo
  (`regsvr32 /i:http scrobj.dll`), `mshta http://`, `mshta vbscript:`,
  `certutil -decode`, `bitsadmin /transfer`, plaintext
  `IEX (New-Object Net.WebClient).DownloadString`, and a
  `-EncodedCommand` wrapping `[Reflection.Assembly]::Load`.

## Results

```
TP = 10/10
FP = 0/24
FN = 0
```

Severity discrimination held:

- Admin-dual-use LOLBAS (`certutil -decode`, `bitsadmin /transfer`)
  scored **medium** (`high_severity=false`).
- Attack-specific patterns (squiblydoo/squiblytwo, mshta remote,
  IEX+WebClient, decoded `-EncodedCommand` with stage-one markers)
  scored **high** (`high_severity=true`).

## Running

```bash
python3 analysis/t1140_validation/realworld_cmdlines.py \
  > analysis/t1140_validation/results.json \
  2> analysis/t1140_validation/summary.txt
```

## Not Validated Here

End-to-end MemoryDetector wiring against a live memory dump.
`scenarios/training/network_intrusion/evidence/ggmemday1.dmp` was the
only real memory artifact in the tree, but it is a Linux dump whose
kernel has no matching ISF in the stock Volatility 3 symbol cache —
`linux.psaux` rejects with unsatisfied kernel requirements. Tracked
in follow-up issue **SFE-2hb**: land a Windows memory dump (or the
matching Linux ISF) and wire the CLI path through the full parse →
MemoryDetector → T1140 finding chain.
