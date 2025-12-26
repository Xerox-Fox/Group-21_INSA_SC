rule ASP_Webshell_Common
{
  meta:
    author = "NeuroCrypt"
    description = "ASP/ASPX webshell detection (Request.Form, Execute, Eval)"
    severity = "high"

  strings:
    $s_request_form = /Request\.(Form|QueryString)\(/
    $s_exec         = /Execute\s*\(/i
    $s_eval         = /Eval\s*\(/i
    $s_server_create= /Server\.CreateObject\s*\(/
    $s_base64       = /Base64Decode|Server\.URLDecode/

  condition:
    (any of ($s_*)) and filesize < 3MB
}
