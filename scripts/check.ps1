$ErrorActionPreference = 'Stop'

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host "==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$goFiles = @(git ls-files '*.go')
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to list tracked Go files'
}

Invoke-Check 'go mod tidy -diff' { go mod tidy -diff }
Invoke-Check 'go mod verify' { go mod verify }

Write-Host '==> gofmt check'
$unformatted = @(gofmt -l $goFiles)
if ($LASTEXITCODE -ne 0) {
    throw "gofmt failed with exit code $LASTEXITCODE"
}
if ($unformatted.Count -gt 0) {
    $unformatted | ForEach-Object { Write-Error "Unformatted Go file: $_" }
    throw 'gofmt check failed'
}

Invoke-Check 'go vet ./...' { go vet ./... }
Invoke-Check 'go test ./...' { go test ./... }
$cgoEnabled = go env CGO_ENABLED
if ($LASTEXITCODE -ne 0) {
    throw "Unable to determine CGO_ENABLED (exit code $LASTEXITCODE)"
}
if ($cgoEnabled -eq '1') {
    Invoke-Check 'go test -race ./...' { go test -race ./... }
} else {
    Write-Warning "Skipping go test -race ./... because CGO_ENABLED=$cgoEnabled"
}
Invoke-Check 'go build ./...' { go build ./... }

Write-Host 'All local checks passed.'
