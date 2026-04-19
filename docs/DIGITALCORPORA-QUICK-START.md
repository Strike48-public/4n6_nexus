# Digital Corpora - Quick Start Guide

Fast-track guide to downloading and using comprehensive DFIR training datasets.

## TL;DR - Start Now

```bash
cd /home/jtomek/Code/sift_find_evil/scripts/download-corpora

# Download essential training data (~140 GB, 2-6 hours)
./download-phase1-critical.sh

# Verify integrity
./verify-downloads.sh

# Extract and start learning
cd ../../scenarios/nitroba
# Begin analysis with smallest scenario
```

## What You Get

### Phase 1: Critical (~140 GB) - START HERE

**Mobile Forensics:**
- Android 10, 11, 12 (modern versions)
- iOS 13.3.1, 13.4.1
- Real device images, not simulated

**Disk Forensics:**
- NPS test images (NTFS, FAT32, ext3, HFS+)
- File carving, fragmentation, encryption
- Windows XP with user artifacts

**Scenarios (with solutions available):**
- Nitroba: Network harassment (53 MB - start here!)
- M57-Jean: Corporate espionage (3 GB)
- M57-Patents: Complex multi-drive case (15 GB)
- National Gallery 2012: Web server compromise (5 GB)

**Files:**
- 10,000 real government documents (Govdocs1 subsets)
- Variety of file types, formats, encodings

**Network:**
- 5 GB TCP connection for reassembly testing
- PCAPs included in scenarios

**SQL:**
- SQLite databases from various sources
- Browser artifacts, app data

### Phase 2: High (~100 GB) - AFTER PHASE 1

- Android 13 (latest), Android 8-9 (coverage)
- Modern scenarios (2018-2019: Lone Wolf, Narcos, Owl, Tuck)
- 109,000 JPEG images from Govdocs1
- Foreign language file systems

### Phase 3: Selective (Variable) - ON DEMAND

- Full Govdocs1 (~250 GB) - only if needed
- DEFCON CTF (~50 GB) - for CTF training
- Legacy devices - historical interest
- PDF security corpora - specialized research

## Recommended Learning Path

### Week 1: Network Forensics
1. Start with **Nitroba** scenario (53 MB)
2. PCAP analysis with Wireshark
3. HTTP reconstruction, email analysis
4. Network timeline

**Skills:** Wireshark, tshark, NetworkMiner, packet analysis

### Week 2: Disk Forensics - Windows
1. Analyze **M57-Jean** scenario (3 GB)
2. Windows XP disk image
3. Registry, MFT, VSS, Prefetch
4. Timeline analysis

**Skills:** Autopsy, Sleuth Kit, Registry Explorer, Timeline Explorer

### Week 3: Mobile Forensics
1. Android 10 or 11 image
2. File system analysis
3. SQLite database extraction
4. App artifact recovery

**Skills:** Autopsy mobile module, SQLite browser, Android file systems

### Week 4: Complex Scenario
1. **M57-Patents** scenario (15 GB)
2. Multiple disks, network, memory
3. Multi-source correlation
4. Timeline pivoting

**Skills:** End-to-end investigation, correlation, report writing

## Storage Planning

| If you have... | Download... | Get... |
|----------------|-------------|---------|
| 150 GB free | Phase 1 | Essential training foundation |
| 250 GB free | Phase 1 + 2 | Comprehensive DFIR coverage |
| 500+ GB free | All phases | Research-grade dataset |

## Quick Commands

### Check Available Space
```bash
df -h /home/jtomek/Code/sift_find_evil
```

### Download Phase 1
```bash
cd /home/jtomek/Code/sift_find_evil/scripts/download-corpora
./download-phase1-critical.sh
```

### Verify Downloads
```bash
./verify-downloads.sh
```

### Extract Archives
```bash
cd ../../scenarios

# ZIP files
cd mobile/android
unzip android_12.zip

# TAR.GZ files
tar -xzf android_9.tar.gz

# Back to base
cd ../..
```

### Start with Nitroba
```bash
cd scenarios/nitroba
ls -lh
# Review README files
# Open PCAP in Wireshark
wireshark 2008-nitroba.pcap
```

## Integration with SIFT Tools

All datasets work with SIFT Workstation:

### Disk Images
```bash
# Mount E01 with ewfmount
ewfmount image.E01 /mnt/ewf

# Analyze with Autopsy
autopsy

# Or Sleuth Kit commands
fls -r /mnt/ewf/ewf1
```

### Memory Images (M57-Patents)
```bash
# Volatility 3
python3 /opt/volatility3-2.20.0/vol.py -f memory.raw windows.info
python3 /opt/volatility3-2.20.0/vol.py -f memory.raw windows.pstree
```

### Network Captures
```bash
# Wireshark GUI
wireshark capture.pcap

# Or tshark for CLI
tshark -r capture.pcap -Y "http" -T fields -e http.host

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,./extracted/
```

### Mobile Images
```bash
# Autopsy has Android/iOS analysis modules
# Or use adb for Android
adb shell
```

## Scenario Solutions

Solutions are available by request:

1. Visit: https://digitalcorpora.org/corpora/scenarios/obtaining-solutions/
2. Email: corpus@digitalcorpora.org
3. Explain your use case (education, research, training)

**Pro tip:** Try solving scenarios yourself first - the learning is in the struggle!

## Common Issues

### Download interrupted?
Scripts use resume support - just run again:
```bash
./download-phase1-critical.sh  # Continues where it left off
```

### Verification failed?
```bash
./verify-downloads.sh           # Shows which files failed
rm failed_file.zip              # Delete corrupt file
./download-phase1-critical.sh   # Re-downloads only missing files
```

### Out of space mid-download?
```bash
# Phase 1 is ~140 GB - make sure you have at least 150 GB free
df -h .

# Delete individual datasets if needed
rm -rf scenarios/reference/mobile/android/android_12.zip  # 42 GB freed
```

## Pro Tips

1. **Start small:** Nitroba is 53 MB and solvable in a few hours
2. **Verify first:** Always run `verify-downloads.sh` after downloading
3. **Keep evidence pristine:** Work on copies, never modify originals
4. **Document everything:** Practice report writing for each scenario
5. **Time yourself:** Professional efficiency matters
6. **Use write blockers:** Even in training, build good habits
7. **Check solutions:** After solving, compare with official solutions

## Next Steps

1. **Run Phase 1 download** - Get essential datasets
2. **Verify integrity** - Ensure clean downloads
3. **Extract archives** - Unzip/untar as needed
4. **Read catalog** - Review full catalog in `docs/digitalcorpora-comprehensive-catalog.md`
5. **Start with Nitroba** - Easiest scenario to build confidence
6. **Progress systematically** - Follow the learning path above
7. **Download Phase 2** - When ready for more

## Resources

- **Full Catalog:** `/home/jtomek/Code/sift_find_evil/docs/digitalcorpora-comprehensive-catalog.md`
- **Download Scripts:** `/home/jtomek/Code/sift_find_evil/scripts/download-corpora/`
- **Digital Corpora Website:** https://digitalcorpora.org/
- **Scenarios Page:** https://digitalcorpora.org/corpora/scenarios/
- **SANS FOR508:** Uses many of these datasets

## Fast Internet? Download Now!

You mentioned you have fast internet NOW - here's the best use of it:

```bash
# 1. Start Phase 1 (will run for 2-6 hours)
cd /home/jtomek/Code/sift_find_evil/scripts/download-corpora
nohup ./download-phase1-critical.sh > phase1.log 2>&1 &

# 2. Check progress
tail -f phase1.log

# 3. When Phase 1 completes, verify
./verify-downloads.sh

# 4. If clean, start Phase 2 immediately
nohup ./download-phase2-high.sh > phase2.log 2>&1 &

# 5. Total download time: 3-10 hours for both phases (~240 GB)
#    With fast internet, you'll have comprehensive DFIR training data by end of day!
```

Then you can practice whenever you want, regardless of internet speed.

---

**Ready to start?** Jump to [Quick Commands](#quick-commands) above!

**Want details?** Read the [Full Catalog](/home/jtomek/Code/sift_find_evil/docs/digitalcorpora-comprehensive-catalog.md)

**Have questions?** Check [Common Issues](#common-issues) or email corpus@digitalcorpora.org
