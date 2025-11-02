rule UPX_Packed
{
    strings:
        $s1 = "UPX!" ascii nocase
    condition:
        $s1
}

