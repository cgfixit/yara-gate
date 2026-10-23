rule container_disk_image {
    meta:
        id = "container_disk_image"
        author = "yara-gate"
        description = "ISO, VHD, or DMG magic at the structural offset"
        intent = "Advisory when a file has ISO, VHD, or DMG magic at the offset that format uses"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    condition:
        (filesize > 0x8005 and
            uint8(0x8001) == 0x43 and uint8(0x8002) == 0x44 and
            uint8(0x8003) == 0x30 and uint8(0x8004) == 0x30 and uint8(0x8005) == 0x31) or
        (filesize > 512 and uint32(filesize - 512) == 0x656e6f63) or
        (filesize > 512 and uint32(filesize - 512) == 0x796c6f6b)
}
