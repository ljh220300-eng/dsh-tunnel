@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 打包 DSH 隧道工具为 exe

where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.8+ 并勾选 "Add python.exe to PATH"。
    echo 下载地址：https://www.python.org/downloads/
    pause
    exit /b 1
)

echo 正在安装依赖（paramiko + pyinstaller）...
python -m pip install -r requirements.txt pyinstaller
echo.

python -m PyInstaller --noconfirm --onefile --windowed --name "DSH云服务一键隧道" dsh_tunnel.py

if errorlevel 1 (
    echo.
    echo [错误] 打包失败，请查看上方日志。
    pause
    exit /b 1
)

echo.
echo 打包完成：dist\DSH云服务一键隧道.exe
echo 注意：config.json 与 keys 目录会生成在 exe 所在目录。
pause
