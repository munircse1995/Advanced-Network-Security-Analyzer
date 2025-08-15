@echo off
setlocal

:: Create desktop shortcut for Network Analyzer
set "TARGET=%~dp0RunNetworkAnalyzer.bat"
set "SHORTCUT=%USERPROFILE%\Desktop\Network Security Analyzer.lnk"
set "ICON=%~dp0network_analyzer.ico"

:: Download icon if missing
if not exist "%ICON%" (
    echo Downloading application icon...
    bitsadmin /transfer downloadIcon /download /priority normal "https://raw.githubusercontent.com/microsoft/fluentui-emoji/main/assets/Shield%20Light/Default/3D/shield_light_3d_default.png" "%ICON%"
)

:: Create shortcut using PowerShell
PowerShell -NoProfile -Command ^
    "$ws = New-Object -ComObject WScript.Shell;" ^
    "$sc = $ws.CreateShortcut('%SHORTCUT%');" ^
    "$sc.TargetPath = '%TARGET%';" ^
    "$sc.WorkingDirectory = '%~dp0';" ^
    "$sc.WindowStyle = 1;" ^
    "if (Test-Path '%ICON%') { $sc.IconLocation = '%ICON%' };" ^
    "$sc.Save()"

echo Shortcut created on desktop: "Network Security Analyzer.lnk"
echo.
echo Double-click to run the Advanced Network Security Analyzer
pause