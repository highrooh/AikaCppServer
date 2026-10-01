@echo off
setlocal

set "SERVER_EXE=%~dp0build\Release\aika_server.exe"
set "SERVER_ROOT=%~dp0build\Release"

if not "%~1"=="" set "SERVER_ROOT=%~1"

if not exist "%SERVER_EXE%" (
    echo Executavel C++ nao encontrado:
    echo   %SERVER_EXE%
    echo Compile o projeto com CMake antes de iniciar.
    pause
    exit /b 1
)

if not exist "%SERVER_ROOT%\AikaServer.ini" (
    echo Configuracao do servidor nao encontrada em:
    echo   %SERVER_ROOT%
    echo Passe a pasta Bin como argumento ou ajuste SERVER_ROOT neste arquivo.
    pause
    exit /b 1
)

echo Iniciando o servidor Aika C++...
echo Raiz: %SERVER_ROOT%
echo Mantenha esta janela aberta. Pressione Ctrl+C para encerrar.
echo.
"%SERVER_EXE%" "%SERVER_ROOT%"
set "SERVER_EXIT=%ERRORLEVEL%"

if not "%SERVER_EXIT%"=="0" echo Servidor encerrado com codigo %SERVER_EXIT%.
pause
exit /b %SERVER_EXIT%
