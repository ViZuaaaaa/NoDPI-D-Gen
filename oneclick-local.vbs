' D-Gen one-click entrypoint (no console window)

Option Explicit

Dim shell, fso, scriptDir, ps, launcher, cmd

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
launcher = scriptDir & "\D-Gen\launcher.ps1"

cmd = """" & ps & """" & " -NoProfile -ExecutionPolicy Bypass -STA -File " & """" & launcher & """" 

' 0 = hidden window, False = do not wait
shell.Run cmd, 0, False
