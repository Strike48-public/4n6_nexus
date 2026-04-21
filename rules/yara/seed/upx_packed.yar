rule upx_packed {
    meta:
        author = "sift_find_evil"
        description = "Detects UPX section names in a PE (common malware packer)"
        severity = "medium"
        mitre_attack = "T1027.002"
        reference = "https://upx.github.io/"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_sig = "UPX!"
    condition:
        2 of them
}
