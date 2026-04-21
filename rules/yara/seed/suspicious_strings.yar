rule suspicious_cmd_execution_strings {
    meta:
        author = "sift_find_evil"
        description = "Common cmd / powershell execution strings in binaries"
        severity = "medium"
        mitre_attack = "T1059.003"
    strings:
        $a1 = "cmd.exe /c" nocase
        $a2 = "powershell -enc" nocase
        $a3 = "WScript.Shell" nocase
        $a4 = "rundll32.exe" nocase
        $a5 = "regsvr32.exe /s /n /u /i:" nocase
    condition:
        any of them
}

rule suspicious_network_api_strings {
    meta:
        author = "sift_find_evil"
        description = "Common C2/exfil network API strings"
        severity = "medium"
        mitre_attack = "T1071.001"
    strings:
        $a1 = "InternetOpenA"
        $a2 = "InternetConnectA"
        $a3 = "HttpSendRequestA"
        $a4 = "WinHttpSendRequest"
        $a5 = "WSASocketA"
    condition:
        2 of them
}
