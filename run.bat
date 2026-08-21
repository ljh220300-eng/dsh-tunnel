@echo off
chcp 65001 >nul
cd /d "%~dp0"
title DSH 云服务一键隧道

where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.8+ 并勾选 "Add python.exe to PATH"。
    echo 下载地址：https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

python -c "import paramiko" >nul 2>nul
if errorlevel 1 (
    echo 首次运行，正在安装依赖 paramiko ...
    python -m pip install -r requirements.txt
    echo.
)

python dsh_tunnel.py
if errorlevel 1 (
    echo.
    echo [提示] 程序异常退出，请查看上方错误信息。
    pause
)
