@echo off
REM ==================================================
REM   GodMode Server Startup Script (Windows)
REM   Author: Jr (Kyalla Junior)
REM ==================================================

REM Change to project directory
cd /d C:\Users\ADMN\godmode-server

REM Clear screen
cls

echo ==================================================
echo  🚀 Starting GodMode Server (with Nodemon)
echo ==================================================

REM Run the server with auto-restart
npx nodemon server.js

REM Keep window open if something fails
pause
