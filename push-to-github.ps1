$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/manoj1-008/cyberpulse.git"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "Git is required. Install Git for Windows, then rerun this script."
}

if (-not (Test-Path ".git")) {
  git init --initial-branch=main
  if ($LASTEXITCODE -ne 0) { throw "git init failed." }
} else {
  git branch -M main
  if ($LASTEXITCODE -ne 0) { throw "Could not set the current branch to main." }
}

$Remote = git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0 -and $Remote -and $Remote.Trim() -ne $RepoUrl) {
  throw "An origin remote already exists but points elsewhere: $Remote. Review it manually; this script will not overwrite it."
}
if (-not $Remote) {
  git remote add origin $RepoUrl
  if ($LASTEXITCODE -ne 0) { throw "Could not add the GitHub origin remote." }
}

git add -A
if ($LASTEXITCODE -ne 0) { throw "git add failed." }
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
  git commit -m "feat: initial CyberGuard Pulse MVP"
  if ($LASTEXITCODE -ne 0) { throw "git commit failed. Configure git user.name and user.email if needed." }
} else {
  Write-Host "No new file changes to commit."
}

git push -u origin main
if ($LASTEXITCODE -ne 0) {
  throw "Push failed. Sign in with Git Credential Manager and confirm write access to $RepoUrl, then rerun this script."
}
Write-Host "Source uploaded to $RepoUrl"
