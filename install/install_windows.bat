@echo off
setlocal
set "SOURCE_DIR=%~dp0..\ghidra_scripts"
set "TARGET_DIR=%USERPROFILE%\ghidra_scripts"
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
copy /Y "%SOURCE_DIR%\AnalyzePLCProgramPlusV2.java" "%TARGET_DIR%\AnalyzePLCProgramPlusV2.java" >nul || goto :error
copy /Y "%SOURCE_DIR%\RecoverAndDecompilePLC.java" "%TARGET_DIR%\RecoverAndDecompilePLC.java" >nul || goto :error
echo Installed both scripts to %TARGET_DIR%
exit /b 0
:error
echo Installation failed.
exit /b 1
