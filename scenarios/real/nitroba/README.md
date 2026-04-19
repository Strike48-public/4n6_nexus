# Nitroba University Harassment Scenario (2008)

Harassing emails traced to a dorm-room IP shared by three students plus an open Wi-Fi router. Network tap captured traffic on the Monday a new email was sent.

See [`scenario.yaml`](scenario.yaml) for the manifest.

## Evidence

| File | Size |
|---|---|
| `evidence/nitroba.pcap` | 54 MB |

Download: `./download_all.sh` (fetches PCAP into `evidence/` and teaching materials into `teaching_materials/`).

## Scenario brief

- Victim: Lily Tuckridge (lilytuckrige@yahoo.com)
- Source IP: 140.247.62.34 (student dorm)
- Network: Ethernet + open Wi-Fi router
- Key date: Monday 2008-07-21

## Investigation goal

Determine which student in Chem 109 sent the harassing email and provide clear evidence.

## Files in this directory

| File | Purpose |
|---|---|
| [`scenario.yaml`](scenario.yaml) | Manifest |
| [`NITROBA_SCENARIO_INFO.md`](NITROBA_SCENARIO_INFO.md) | Full background with URLs/hashes |
| [`files_manifest.json`](files_manifest.json) | Machine-readable evidence list |
| [`download_all.sh`](download_all.sh) | Fetches PCAP + teaching materials |
| [`DOWNLOAD_URLS.txt`](DOWNLOAD_URLS.txt) | Flat list of download URLs |
| `analysis/` | Analyst working notes (if any) |

## Reproduction

```bash
tshark -r scenarios/real/nitroba/evidence/nitroba.pcap -Y "http.request" | head
```
