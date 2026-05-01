$ips = @(
  # 🇮🇳 India
  "49.36.0.1","103.27.8.1","106.51.0.5",

  # 🇺🇸 USA
  "8.8.8.8","44.192.0.1","52.95.110.1",

  # 🇷🇺 Russia
  "5.255.255.5","77.88.55.1",

  # 🇨🇳 China
  "36.110.0.1","123.125.114.1",

  # 🇩🇪 Germany
  "18.194.0.1","3.121.0.1",

  # 🇧🇷 Brazil
  "177.154.0.1","200.147.67.1"
)

$attacks = @(
  "SQL_INJECTION_ATTEMPT",
  "SSH_BRUTEFORCE",
  "XSS_ATTACK",
  "IDOR_ATTACK",
  "PORT_SCAN",
  "LOGIN_BRUTEFORCE"
)

$endpoints = @(
  "/login",
  "/api/user",
  "/admin",
  "/transfer",
  "/dashboard"
)

$protocols = @(
  "HTTP",
  "SSH",
  "TCP"
)

while ($true) {

  $attack = $attacks | Get-Random
  $ip = $ips | Get-Random

  $log = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
    event_id = [guid]::NewGuid().ToString()
    honeypot_service = "banking-portal"
    source_ip = $ip
    attack_type = $attack
    username = "admin"
    password = "123456"
    endpoint = $endpoints | Get-Random
    severity = (Get-Random -InputObject @("LOW","MEDIUM","HIGH"))
    details = "$attack detected from $ip"
    protocol = $protocols | Get-Random
    environment = "honeypot-finance"
    project = "PRJN26-213"
  }

  $json = $log | ConvertTo-Json -Compress

  $client = New-Object System.Net.Sockets.TcpClient("localhost",5000)
  $stream = $client.GetStream()
  $writer = New-Object System.IO.StreamWriter($stream)

  $writer.WriteLine($json)
  $writer.Flush()
  $writer.Close()
  $client.Close()

  Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 1500)
}