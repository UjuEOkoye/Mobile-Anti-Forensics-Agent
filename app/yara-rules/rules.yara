rule DFIR_RWX_MARKER_Prefix
{
  meta:
    author = "you"
    description = "Detect DFIR RWX experiment markers: DFIR_RWX_MARKER_* (ASCII/UTF-16LE)"
    version = "1.0"

  strings:
    $m_ascii = /DFIR_RWX_MARKER_[A-Za-z0-9._:-]{1,80}/ ascii
    $m_wide  = /DFIR_RWX_MARKER_[A-Za-z0-9._:-]{1,80}/ wide

  condition:
    any of them
}