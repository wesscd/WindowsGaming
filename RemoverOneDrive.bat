@echo off
cls
set x86="%SYSTEMROOT%\System32\OneDriveSetup.exe"
set x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"

echo Encerrando processos do OneDrive...
taskkill /f /im OneDrive.exe > NUL 2>&1
timeout /t 5 > NUL 2>&1

echo Desinstalando o OneDrive...
if exist %x64% (
    %x64% /uninstall
) else (
    %x86% /uninstall
)
timeout /t 5 > NUL 2>&1

echo Removendo restos do OneDrive...
rd "%USERPROFILE%\OneDrive" /Q /S > NUL 2>&1
rd "C:\OneDriveTemp" /Q /S > NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S > NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S > NUL 2>&1

echo Removendo o OneDrive do Explorador de Arquivos...
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1

echo OneDrive removido com sucesso.
echo Reinicie seu computador para concluir o processo.
pause
