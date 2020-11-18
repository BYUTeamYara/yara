rule foundstring
{
	strings:
		$text_string = "C3HQS750B"
	
	condition:
		$text_string
}
