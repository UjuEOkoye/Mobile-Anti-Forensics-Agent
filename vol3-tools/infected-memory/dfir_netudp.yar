rule DFIR_NETUDP_MARKER
{
    meta:
        description = "Detect DFIR UDP marker string in process memory"
        author = "Souhardya"
        date = "2026-02-26"

    strings:
        $marker = /DFIR_NETUDP_MARKER_[A-Za-z0-9]+/ ascii wide

    condition:
        $marker
}