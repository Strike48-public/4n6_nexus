rule eicar_test_string {
    meta:
        author = "sift_find_evil"
        description = "EICAR antimalware test string. Matches the harmless test vector defined by eicar.org — not real malware."
        severity = "high"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
