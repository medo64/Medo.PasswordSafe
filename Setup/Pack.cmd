@ECHO OFF
SETLOCAL EnableDelayedExpansion

SET TOOLS_MSBUILD="%PROGRAMFILES(X86)%\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\amd64\msbuild.exe"


ECHO --- DISCOVER TOOLS
ECHO:

FOR %%I IN (%TOOLS_MSBUILD%) DO (
    IF EXIST %%I IF NOT DEFINED TOOL_MSBUILD SET TOOL_MSBUILD=%%I
)
ECHO MSBuild: %TOOL_MSBUILD%
IF [%TOOL_MSBUILD%]==[] ECHO Not found^^! & GOTO Error

ECHO:
ECHO:


ECHO --- PACK
ECHO:

DEL "..\Binaries\*.0.0.0.nupkg" 2> NUL

%TOOL_MSBUILD% /t:pack ..\Source\PasswordSafe\PasswordSafe.csproj /p:IncludeSymbols=true /p:IncludeSource=true /p:Configuration=Release


ENDLOCAL
EXIT /B 0


:Error
ENDLOCAL
PAUSE
EXIT /B 1
