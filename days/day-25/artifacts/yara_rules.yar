/*
 * Day 25 — YARA Rules: Ransomware Detection
 * NovaCrest Capital Group | Digital Forensics
 * Case: NCA-2026-06-R | Strain: ncrypt (.ncrypt variant)
 *
 * RULES:
 *   1. ncrypt_ransom_note         — Detects ransom note by content patterns
 *   2. ncrypt_file_marker         — Detects .ncrypt encrypted file header
 *   3. ncrypt_binary_strings      — Detects ransomware binary by embedded strings
 *   4. ncrypt_vss_deletion        — Detects VSS deletion commands in memory/prefetch
 *   5. lockbit3_builder_variant   — Broad LockBit 3.0 builder characteristics
 *   6. ncrypt_mutex_pattern       — Detects anti-double-encryption mutex string
 *   7. ransomware_generic_evasion — Generic ransomware evasion command patterns
 *
 * Usage:
 *   yara -r yara_rules.yar /path/to/scan/
 *   yara -r yara_rules.yar memory_dump.mem
 *   yara --print-strings ncrypt_binary_strings suspicious.exe
 */


/* =====================================================================
 * RULE 1: ncrypt Ransom Note Detection
 * ===================================================================== */
rule ncrypt_ransom_note
{
    meta:
        description    = "Detects NovaCrest ncrypt ransomware note"
        author         = "V. Willis, CISSP — NovaCrest IR"
        date           = "2026-06-19"
        severity       = "Critical"
        technique      = "T1486"
        case           = "NCA-2026-06-R"
        threat_name    = "Ransom.ncrypt"
        reference      = "Internal — NovaCrest SRV-FS-01 incident"

    strings:
        $note_filename  = "!!READ_ME_NOW!!"  ascii wide
        $victim_id      = "NOVA-" ascii       // Victim ID prefix
        $payment_coin   = "Monero" ascii wide nocase
        $payment_coin2  = " XMR" ascii wide
        $onion_site     = ".onion" ascii wide
        $contact_email  = "ncrypt-support" ascii wide
        $encrypt_msg    = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $deadline_msg   = "72 hours" ascii wide nocase

    condition:
        ($note_filename or $encrypt_msg) and
        2 of ($payment_coin, $payment_coin2, $onion_site,
              $contact_email, $deadline_msg, $victim_id)
}


/* =====================================================================
 * RULE 2: ncrypt Encrypted File Marker
 * ===================================================================== */
rule ncrypt_encrypted_file
{
    meta:
        description = "Detects files encrypted by ncrypt ransomware"
        author      = "V. Willis, CISSP"
        date        = "2026-06-19"
        severity    = "High"
        technique   = "T1486"
        note        = "Encrypted files have a 32-byte header prepended before ciphertext"

    strings:
        // ncrypt prepends a custom header: magic bytes + encrypted session key length
        $ncrypt_magic  = { 4E 43 52 59 50 54 56 31 }  // "NCRYPTV1" in hex
        $key_marker    = { 00 10 00 00 }               // 4096-byte RSA key block marker

    condition:
        $ncrypt_magic at 0 and $key_marker at 8
}


/* =====================================================================
 * RULE 3: ncrypt Ransomware Binary (String-Based)
 * ===================================================================== */
rule ncrypt_binary_strings
{
    meta:
        description = "Detects ncrypt ransomware binary by embedded strings"
        author      = "V. Willis, CISSP"
        date        = "2026-06-19"
        severity    = "Critical"
        technique   = "T1486"
        threat_name = "Ransom.ncrypt"
        sha256      = "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3"

    strings:
        // Ransom note embedded in binary
        $s1 = "!!READ_ME_NOW!!" ascii wide
        $s2 = "ncrypt-support@protonmail.com" ascii wide
        $s3 = ".ncrypt" ascii wide
        $s4 = "NOVA-" ascii                          // Victim ID prefix

        // Anti-recovery commands (embedded as string literals)
        $cmd1 = "vssadmin delete shadows /all /quiet" ascii wide nocase
        $cmd2 = "wbadmin delete catalog -quiet" ascii wide nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $cmd4 = "sc stop WinDefend" ascii wide nocase

        // Encryption configuration strings
        $enc1 = "AES-256" ascii wide nocase
        $enc2 = "RSA-4096" ascii wide nocase
        $enc3 = "NovaCryptMutex" ascii            // Mutex name pattern

        // Network / C2 strings
        $net1 = ".onion" ascii wide
        $net2 = "protonmail.com" ascii wide
        $net3 = "WinHttpOpen" ascii               // HTTP client function

    condition:
        uint16(0) == 0x5A4D and          // MZ header (PE file)
        filesize < 20MB and               // Ransomware binaries are usually < 20 MB
        (
            3 of ($s1, $s2, $s3, $s4) or
            2 of ($cmd1, $cmd2, $cmd3, $cmd4) or
            ($enc1 and $enc2 and any of ($net1, $net2))
        )
}


/* =====================================================================
 * RULE 4: VSS and Recovery Deletion Commands
 * ===================================================================== */
rule ransomware_recovery_destruction
{
    meta:
        description = "Detects shadow copy and recovery destruction commands used by ransomware"
        author      = "V. Willis, CISSP"
        date        = "2026-06-19"
        severity    = "Critical"
        technique   = "T1490"
        note        = "Applies to command lines in memory, prefetch, event logs, scripts"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe Delete Shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase
        $wbad = "wbadmin delete catalog" ascii wide nocase
        $bcd1 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $bcd2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $dfrag = "defrag" ascii wide nocase          // Some ransomware uses defrag to overwrite

    condition:
        2 of ($vss1, $vss2, $vss3, $wbad, $bcd1, $bcd2)
}


/* =====================================================================
 * RULE 5: LockBit 3.0 Builder Variant Characteristics
 * ===================================================================== */
rule lockbit3_builder_variant
{
    meta:
        description = "Broad detection for LockBit 3.0 builder-derived ransomware variants"
        author      = "V. Willis, CISSP"
        date        = "2026-06-19"
        severity    = "Critical"
        technique   = "T1486"
        reference   = "LockBit 3.0 builder leaked Sept 2022 — enables custom variants"
        note        = "May produce false positives on legitimate LockBit decryptors"

    strings:
        // LockBit 3.0 characteristic strings (from leaked builder analysis)
        $lb1 = "LockBit" ascii wide nocase
        $lb2 = "LOCKBIT" ascii wide
        $lb3 = { 4C 42 33 }         // "LB3" hex
        
        // Common LockBit 3.0 process termination list (embedded)
        $proc1 = "mysql.exe" ascii wide
        $proc2 = "oracle.exe" ascii wide
        $proc3 = "sqlwriter.exe" ascii wide
        $proc4 = "mspdbsrv.exe" ascii wide

        // LockBit 3.0 file skip list characteristics
        $skip1 = ".lnk" ascii wide
        $skip2 = "ntuser.dat" ascii wide nocase
        $skip3 = "desktop.ini" ascii wide nocase
        $skip4 = "autorun.inf" ascii wide nocase

        // Ransom note delivery method
        $note  = "!!!" ascii                          // Triple-bang in note filename

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($lb1, $lb2, $lb3) or
            (3 of ($proc1, $proc2, $proc3, $proc4) and
             2 of ($skip1, $skip2, $skip3, $skip4))
        ) and $note
}


/* =====================================================================
 * RULE 6: Anti-Double-Encryption Mutex
 * ===================================================================== */
rule ncrypt_mutex_pattern
{
    meta:
        description = "Detects ncrypt mutex pattern in memory or binary"
        author      = "V. Willis, CISSP"
        date        = "2026-06-19"
        severity    = "High"
        technique   = "T1486"
        note        = "Mutex contains victim ID — confirms unique per-victim deployment"

    strings:
        $mutex_prefix = "Global\\NovaCryptMutex_" ascii wide
        $mutex_nova   = "NovaCryptMutex" ascii wide

    condition:
        any of them
}


/* =====================================================================
 * RULE 7: Generic Ransomware File Enumeration Pattern
 * ===================================================================== */
rule ransomware_file_enumeration
{
    meta:
        description = "Detects ransomware-style file enumeration and encryption loop patterns"
        author      = "V. Willis, CISSP"
        date        = "2026-06-19"
        severity    = "Medium"
        technique   = "T1486"
        note        = "Broad rule — may FP on legitimate encryption tools; use with context"

    strings:
        // Win32 API calls typical of ransomware file traversal
        $api1 = "FindFirstFileW" ascii
        $api2 = "FindNextFileW" ascii
        $api3 = "CreateFileW" ascii
        $api4 = "WriteFile" ascii
        $api5 = "MoveFileExW" ascii          // Rename to add extension
        $api6 = "DeleteFileW" ascii          // Delete originals (some strains)

        // Crypto API calls
        $crypt1 = "CryptGenRandom" ascii
        $crypt2 = "BCryptEncrypt" ascii
        $crypt3 = "NCryptEncrypt" ascii
        $crypt4 = "CryptEncrypt" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($api1, $api2, $api3, $api4, $api5, $api6) and
        any of ($crypt1, $crypt2, $crypt3, $crypt4)
}
