@echo off
TITLE Configurar Link Chat-EEL
COLOR 0A
CLS

ECHO ========================================================
ECHO    CONFIGURACION DE NOMBRE PERSONALIZADO (CHAT-EEL)
ECHO ========================================================
ECHO.
ECHO Este script agregara "chat-eel" a tu archivo de hosts.
ECHO Esto te permitira entrar al chat escribiendo: http://chat-eel:3000
ECHO.
ECHO * IMPORTANTE: Debes ejecutar este archivo como ADMINISTRADOR.
ECHO   (Click derecho -> Ejecutar como administrador)
ECHO.
PAUSE

REM Check for Admin privileges
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO.
    ECHO [ERROR] No tienes permisos de Administrador.
    ECHO Por favor, cierra esto, dale click derecho y "Ejecutar como administrador".
    PAUSE
    EXIT /B
)

ECHO.
ECHO Verificando archivo hosts...
FINDSTR /C:"127.0.0.1 chat-eel" "%WINDIR%\System32\drivers\etc\hosts" >nul
IF %ERRORLEVEL% NEQ 0 (
    ECHO Agregando entrada...
    ECHO. >> "%WINDIR%\System32\drivers\etc\hosts"
    ECHO 127.0.0.1 chat-eel >> "%WINDIR%\System32\drivers\etc\hosts"
    ECHO.
    ECHO [EXITO] Entrada agregada correctamente.
) ELSE (
    ECHO [INFO] "chat-eel" ya existe en tu archivo hosts.
)

ECHO.
ECHO ========================================================
ECHO    LISTO! AHORA PUEDES USAR: http://chat-eel:3005
ECHO    (Asegurate que el servidor este corriendo con: node server.js)
ECHO ========================================================
PAUSE
