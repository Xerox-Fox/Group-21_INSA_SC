rule Reverse_Shell_Commands
{
  meta:
    author = "NeuroCrypt"
    description = "Detect reverse-shell command strings in scripts/binaries"
    severity = "critical"

  strings:
    $s_bash_tcp   = /bash\s+-i\s+>&\s+\/dev\/tcp\//
    $s_sh_tcp     = /\/bin\/sh\s+-i\s+>&\s+\/dev\/tcp\//
    $s_nc_exec    = /nc\s+.*-e\s+\/bin\/sh/
    $s_ncat_shell = /ncat\s+.*-e\s+\/bin\/sh/
    $s_python_shell = /python\s+-c\s+['"].*socket.*connect/si

  condition:
    any of them
}
