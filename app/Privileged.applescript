on run argv
	if (count of argv) is not 3 then error "invalid privileged helper arguments"
	set actionName to item 1 of argv
	if actionName is not "enable" and actionName is not "disable" then error "invalid action"
	set helperPath to item 2 of argv
	set configHome to item 3 of argv
	set commandText to "export NETGUARD_HOME=" & quoted form of configHome & "; " & quoted form of helperPath & " " & actionName
	do shell script commandText with administrator privileges
end run
