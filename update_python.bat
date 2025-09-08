@echo off
echo ============================================
echo   Atualizador de Python - Windows
echo ============================================

REM Defina a versão desejada aqui:
set PYTHON_VERSION=3.12.6
set PYTHON_INSTALLER=python-%PYTHON_VERSION%-amd64.exe
set PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/%PYTHON_INSTALLER%

echo Baixando Python %PYTHON_VERSION%...
curl -o %PYTHON_INSTALLER% %PYTHON_URL%

echo Instalando Python %PYTHON_VERSION%...
%PYTHON_INSTALLER% /quiet InstallAllUsers=1 PrependPath=1

echo Removendo instalador...
del %PYTHON_INSTALLER%

echo ============================================
echo Python atualizado com sucesso!
echo ============================================

echo Versão atual:
python --version

pause