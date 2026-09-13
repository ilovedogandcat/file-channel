@echo off
chcp 936 >nul
net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo 请右键这个文件，选择“以管理员身份运行”。
  echo.
  pause
  exit /b 1
)

echo 正在放行文件通道需要的端口（TCP 8765 / UDP 8766）...
netsh advfirewall firewall delete rule name="FileChannel TCP 8765" >nul 2>&1
netsh advfirewall firewall delete rule name="FileChannel UDP 8766" >nul 2>&1
netsh advfirewall firewall add rule name="FileChannel TCP 8765" dir=in action=allow protocol=TCP localport=8765 profile=any
netsh advfirewall firewall add rule name="FileChannel UDP 8766" dir=in action=allow protocol=UDP localport=8766 profile=any
echo.
echo 完成。现在对方就能连到这台电脑了。
echo.
pause