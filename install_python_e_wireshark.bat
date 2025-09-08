@echo off
echo ============================================
echo   Instalador Automático: Python + Wireshark
echo ============================================

REM ===== CONFIGURAÇÕES =====
set PYTHON_VERSION=3.12.6
set PYTHON_INSTALLER=python-%PYTHON_VERSION%-amd64.exe
set PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/%PYTHON_INSTALLER%
set PYTHON_PATH=C:\Program Files\Python%PYTHON_VERSION:~0,4%

set WIRESHARK_VERSION=4.2.6
set WIRESHARK_INSTALLER=Wireshark-win64-%WIRESHARK_VERSION%.exe
set WIRESHARK_URL=https://2.na.dl.wireshark.org/win64/%WIRESHARK_INSTALLER%
set WIRESHARK_PATH=C:\Program Files\Wireshark

echo.
echo ===== INSTALANDO PYTHON %PYTHON_VERSION% =====
if not exist %PYTHON_INSTALLER% (
    echo Baixando Python %PYTHON_VERSION%...
    curl -L -o %PYTHON_INSTALLER% %PYTHON_URL%
) else (
    echo Instalador Python ja existe: %PYTHON_INSTALLER%
)

echo Instalando Python (modo silencioso)...
%PYTHON_INSTALLER% /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

REM ===== CONFIGURAR VARIAVEL PYTHON =====
setx PYTHON_HOME "%PYTHON_PATH%"
echo Verificando Python...
python --version

echo.
echo ===== INSTALANDO WIRESHARK %WIRESHARK_VERSION% =====
if not exist %WIRESHARK_INSTALLER% (
    echo Baixando Wireshark %WIRESHARK_VERSION%...
    curl -L -o %WIRESHARK_INSTALLER% %WIRESHARK_URL%
) else (
    echo Instalador Wireshark ja existe: %WIRESHARK_INSTALLER%
)

echo Instalando Wireshark (modo silencioso)...
%WIRESHARK_INSTALLER% /S

REM ===== CONFIGURAR VARIAVEL WIRESHARK =====
setx WIRESHARK_HOME "%WIRESHARK_PATH%"

REM ===== ADICIONANDO AO PATH =====
echo Adicionando Python e Wireshark ao PATH...
echo %PATH% | find /I "%PYTHON_PATH%" >nul
if %ERRORLEVEL% neq 0 (
    setx PATH "%PYTHON_PATH%;%PATH%"
    echo Python adicionado ao PATH.
) else (
    echo Python ja estava no PATH.
)

echo %PATH% | find /I "%WIRESHARK_PATH%" >nul
if %ERRORLEVEL% neq 0 (
    setx PATH "%WIRESHARK_PATH%;%PATH%"
    echo Wireshark adicionado ao PATH.
) else (
    echo Wireshark ja estava no PATH.
)

echo ============================================
echo Instalacao concluida!
echo Reinicie o CMD para que o PATH seja atualizado.
echo ============================================

pause