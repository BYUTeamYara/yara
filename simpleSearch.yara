rule simpleSearch
{
    strings:
        $my_text_string = "bongcloud"
        $my_text_string2 = "lichess"

    condition:
        $my_text_string and $my_text_string2
}

