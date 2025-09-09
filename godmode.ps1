<# ==================================================
   GodMode Server Dashboard
   Author: Jr (Marshall Kyalla Junior)
   ================================================== #>

# Project path
$projectPath = "C:\Users\ADMN\godmode-server"
$logPath = "$projectPath\logs"

# Ensure logs folder exists
If (!(Test-Path -Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath | Out-Null
}

# Functions
function Start-Server {
    Clear-Host
    Write-Host "🚀 Starting GodMode Server with Nodemon..." -ForegroundColor Green
    npx nodemon server.js 2>&1 | Tee-Object -FilePath "$logPath\server-$(Get-Date -Format yyyyMMdd-HHmmss).log"
}

function View-Logs {
    Clear-Host
    Write-Host "📜 Available Logs:" -ForegroundColor Cyan
    Get-ChildItem $logPath -Filter *.log | Sort-Object LastWriteTime -Descending | ForEach-Object {
        Write-Host $_.Name -ForegroundColor Yellow
    }
    $latest = Get-ChildItem $logPath -Filter *.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host "`nOpening latest log ($($latest.Name))..." -ForegroundColor Green
        notepad $latest.FullName
    } else {
        Write-Host "⚠️ No logs found." -ForegroundColor Red
    }
    Pause
}

function Stop-Server {
    Clear-Host
    Write-Host "🛑 Stopping all Node/Nodemon processes..." -ForegroundColor Red
    Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "✅ Server stopped." -ForegroundColor Green
    Pause
}

function Menu {
    do {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      🧩 G SERVER DASHBOARD –Marshall Kyalla Junior" -ForegroundColor Yellow
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "1. 🚀 Start Server" -ForegroundColor Green
        Write-Host "2. 📜 View Latest Logs" -ForegroundColor Yellow
        Write-Host "3. 🛑 Stop Server" -ForegroundColor Red
        Write-Host "4. ❌ Exit" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        $choice = Read-Host "Select an option [1-4]"

        switch ($choice) {
            "1" { Start-Server }
            "2" { View-Logs }
            "3" { Stop-Server }
            "4" { break }
            default { Write-Host "⚠️ Invalid choice. Try again." -ForegroundColor Red; Pause }
        }
    } while ($choice -ne "4")
}

# Run menu
Menu
