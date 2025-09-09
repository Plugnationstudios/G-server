# =========================
# God-Mode Auto Git Push
# Author: Marshall Junior Kyalla
# =========================

# Go to project root (optional if already there)
Set-Location -Path "C:\Users\ADMN\godmode-server"

# Pull latest changes to avoid conflicts
git pull origin main

# Stage all changes
git add .

# Create commit message with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$commitMsg = "God-Mode Update: $timestamp"

# Commit
git commit -m $commitMsg

# Push to GitHub
git push origin main

Write-Host "✅ All changes pushed to GitHub successfully!" -ForegroundColor Green
