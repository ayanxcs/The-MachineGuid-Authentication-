@echo off
for /f "tokens=3" %%a in ('reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid') do (
    set MachineGuid=%%a
)

echo Machine GUID: %MachineGuid%
echo %MachineGuid% | clip

echo The Machine GUID has been copied to your clipboard.
pause
