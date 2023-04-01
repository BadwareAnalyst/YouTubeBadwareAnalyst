import "pe"

rule APT_SharpPanda_Agent
{
	meta:
		description = "Detects APT SharpPanda Agent (51205F6CA73745B97B77095A2BFD7091)"
		author = "Badware Analyst (https://www.youtube.com/@BadwareAnalyst)"
	strings:
		$string1 = "C:\\Users\\user\\Desktop\\0814-surexe\\x64\\SurvExe\\x64\\Release\\SurvExe.pdb" ascii wide nocase
		$string2 = "OEJFISDOFJDLK" ascii wide nocase
	condition:
		// MZ signature
		uint16(0) == 0x5a4d and
		// Size of file
		filesize < 100KB and
		// strings
		$string1 and $string2
}
