# Ensure the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator"
    exit 1
}

$hostname = "ns1.example.com"
$ip = "127.0.0.1"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

# Function to escape dots for regex
function Make-Regex($input) {
    return ($input -replace '\.', '\.')
}

$regex = "^\s*$(Make-Regex $ip)\s+$(Make-Regex $hostname)\s*$"

# Read hosts file content
$hostsContent = Get-Content -Path $hostsPath

# Check if the entry exists
if ($hostsContent -match $regex) {
    Write-Host "Removing entry: $ip $hostname"
    # Remove matching lines
    $newContent = $hostsContent | Where-Object { $_ -notmatch $regex }
    # Save updated hosts file
    $newContent | Set-Content -Path $hostsPath -Encoding ASCII
} else {
    Write-Host "No matching entry found: $ip $hostname"
}

# Flush DNS cache
Write-Host "Flushing DNS cache..."
ipconfig /flushdns | Out-Null

# Test hostname resolution
Write-Host "Testing resolution for $hostname..."
try {
    $pingResult = Test-Connection -ComputerName $hostname -Count 1 -Quiet
    if ($pingResult) {
        Write-Host "$hostname still resolves. Entry may not have been removed properly."
    } else {
        Write-Host "$hostname no longer resolves (expected)."
    }
} catch {
    Write-Host "$hostname no longer resolves (expected)."
}