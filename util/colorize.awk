#!/usr/bin/env -S awk -f
# pipe topologyd output through this script for colorized error messages

function color_print(code, text) {
	printf "\033[%sm%s\033[0;0m\n", code, text
}

$4 == "Warning:" || $4 == "Warning" {
	color_print("34;1", $0)
	next
}
$4 == "Error:" || $4 == "Error" || $0 ~ /HTTP GET.*Internal Server Error/ {
	color_print("31;3", $0)
	next
}

$4 == "debug:" {
	color_print("44", $0)
	next
}
$4 == "debug1:" {
	color_print("44;3", $0)
	next
}

{
	print
}
