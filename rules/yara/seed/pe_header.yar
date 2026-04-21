rule pe_header {
    meta:
        author = "sift_find_evil"
        description = "Detects a PE/DOS MZ header at file offset 0"
        severity = "low"
        reference = "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and filesize > 64
}
