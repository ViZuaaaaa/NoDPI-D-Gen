' D-Gen | https://t.me/DisappearGen
' D-Gen one-click entrypoint (no console window)

Option Explicit

Dim shell, shApp, fso, scriptDir, ps, launcher, args
Set shell = CreateObject("WScript.Shell")
' D-Gen | https://t.me/DisappearGen
Set shApp = CreateObject("Shell.Application")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
launcher = scriptDir & "\D-Gen\launcher.ps1"

args = "-NoProfile -ExecutionPolicy Bypass -STA -File " & """" & launcher & """" 

' 0 = hidden window
shApp.ShellExecute ps, args, scriptDir, "runas", 0
