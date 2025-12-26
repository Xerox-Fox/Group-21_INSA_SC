rule ELF_Suspicious
{
  meta:
    author = "NeuroCrypt"
    description = "Detect ELF binaries with embedded reverse shell or suspicious command strings"
    severity = "high"

  strings:
    $s_bin_sh   = "/bin/sh"
    $s_dev_tcp  = "/dev/tcp"
    $s_exec_sh  = "execve"
    $s_socket   = "socket"

  condition:
    uint32(0) == 0x464c457f and any of ($s_*)   // ELF magic + any string
}
