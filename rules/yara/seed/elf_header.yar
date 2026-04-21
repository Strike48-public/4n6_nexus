rule elf_header {
    meta:
        author = "sift_find_evil"
        description = "Detects an ELF magic header at file offset 0"
        severity = "low"
        reference = "https://refspecs.linuxfoundation.org/elf/elf.pdf"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0 and filesize > 64
}
