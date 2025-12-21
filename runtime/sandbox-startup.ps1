# Get the Host IP (Default Gateway)
$hostIp = (Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).NextHop
Write-Host "Host IP detected: $hostIp"

# Navigate to agent directory (assuming built binary is available)
# Since we map the whole project, we can run from source (need cargo) or binary.
# Windows Sandbox doesn't have Rust installed by default.
# We MUST assume the HOST has built the binary and it's in target/debug or target/release.

$agentPath = "C:\Users\WDAGUtilityAccount\Desktop\loonaro\target\debug\agent.exe"

if (Test-Path $agentPath) {
    Write-Host "Starting Agent connecting to $hostIp..."
    & $agentPath --ip $hostIp
} else {
    Write-Host "Agent binary not found at $agentPath. Please build it on the host first!"
    Read-Host "Press Enter to exit..."
}
