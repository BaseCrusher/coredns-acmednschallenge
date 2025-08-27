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

$regex = "^$(Make-Regex $ip)\s+$(Make-Regex $hostname)$"

# Check if the entry already exists
$hostsContent = Get-Content -Path $hostsPath
if ($hostsContent -match $regex) {
    Write-Host "Entry already exists: $ip $hostname"
} else {
    Write-Host "Adding entry: $ip $hostname"
    "$ip `t$hostname" | Out-File -FilePath $hostsPath -Append -Encoding ASCII
}

# Flush DNS cache
Write-Host "Flushing DNS cache..."
ipconfig /flushdns | Out-Null

# Test hostname resolution
Write-Host "Testing resolution for $hostname..."
try {
    $pingResult = Test-Connection -ComputerName $hostname -Count 1 -Quiet
    if ($pingResult) {
        Write-Host "$hostname resolves successfully to $ip"
    } else {
        Write-Host "Resolution failed. Try 'ping $hostname' manually."
    }
} catch {
    Write-Host "Resolution failed. Try 'ping $hostname' manually."
}