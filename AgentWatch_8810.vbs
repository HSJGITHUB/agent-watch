' Keep this helper beside server.py. Put a shortcut to it in shell:startup.
' Change PYTHON_EXE to a full pythonw.exe path if it is not on PATH.
Option Explicit
Const PYTHON_EXE = "pythonw.exe"
Dim fs, serverPath, shell
Set fs = CreateObject("Scripting.FileSystemObject")
serverPath = fs.BuildPath(fs.GetParentFolderName(WScript.ScriptFullName), "server.py")
Set shell = CreateObject("WScript.Shell")
WScript.Sleep 30000
shell.Run """" & PYTHON_EXE & """ -X utf8 -B """ & serverPath & """ --port 8810", 0, False
