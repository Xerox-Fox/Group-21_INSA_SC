rule PHP_Webshell_Common
{
  meta:
    author = "NeuroCrypt"
    description = "Detect common PHP webshell patterns (eval, assert, base64 wrappers)"
    reference = "custom"
    severity = "high"

  strings:
    $s_eval_post    = /eval\s*\(\s*\$_(POST|REQUEST|GET)\s*\[/
    $s_assert_post  = /assert\s*\(\s*\$_(POST|REQUEST|GET)\s*\[/
    $s_base64_eval  = /base64_decode\s*\(\s*[\$_A-Za-z0-9]+\s*\)/
    $s_shell_exec   = /shell_exec\s*\(/
    $s_eval_decode  = /eval\s*\(\s*base64_decode\s*\(/
    $s_obfuscated   = /preg_replace\s*\(\s*['"].*\/e['"]/

  condition:
    (any of ($s_*) ) and filesize < 5MB
}
