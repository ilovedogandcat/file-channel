@echo off
setlocal
cd /d "%~dp0"

if exist "%~dp0FileChannel.exe" (
  start "" "%~dp0FileChannel.exe"
  exit /b 0
)
if exist "%~dp0dist\FileChannel.exe" (
  start "" "%~dp0dist\FileChannel.exe"
  exit /b 0
)
if exist "%~dp0FileChannel.py" (
  where pythonw >nul 2>nul
  if not errorlevel 1 (
    start "" pythonw "%~dp0FileChannel.py"
    exit /b 0
  )
  where python >nul 2>nul
  if not errorlevel 1 (
    start "" python "%~dp0FileChannel.py"
    exit /b 0
  )
)

echo.
echo 没有找到 FileChannel.exe，也没有找到 Python。
echo 请把整个“文件通道”文件夹一起复制过来。
echo.
pause