# WireGuard Integration Guide - Simple API Flow

This guide shows you exactly how to integrate PIA WireGuard VPN into your application using simple HTTP requests. We'll use Seattle as an example endpoint.

## Prerequisites

- PIA account credentials (username format: `p#######`, password)
- WireGuard client installed on your system
- `ca.rsa.4096.crt` certificate from this repo for SSL verification

## Complete Flow Overview

```
1. Get Authentication Token (POST)
   ↓
2. List All Servers (GET)
   ↓
3. Select Seattle Server & Extract IPs
   ↓
4. Generate WireGuard Keys (local)
   ↓
5. Register with WireGuard Server (GET)
   ↓
6. Create WireGuard Config & Connect
```

---

## Step 1: Get Authentication Token

**Endpoint:** `https://www.privateinternetaccess.com/api/client/v2/token`
**Method:** POST (form data)
**Expiration:** 24 hours

### curl Command:
```bash
curl --location --request POST \
  'https://www.privateinternetaccess.com/api/client/v2/token' \
  --form "username=p0123456" \
  --form "password=your_password_here"
```

### Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### What to Extract:
```javascript
const token = response.token;
// Save this - you'll use it for the next 24 hours
```

---

## Step 2: Get Server List

**Endpoint:** `https://serverlist.piaservers.net/vpninfo/servers/v6`
**Method:** GET
**No Authentication Required**

### curl Command:
```bash
curl -s 'https://serverlist.piaservers.net/vpninfo/servers/v6'
```

### Response Structure:
```json
{
  "regions": [
    {
      "id": "us_seattle",
      "name": "US Seattle",
      "country": "US",
      "geo": false,
      "port_forward": true,
      "servers": {
        "meta": [
          {
            "ip": "173.245.78.142",
            "cn": "seattle402.privateinternetaccess.com"
          }
        ],
        "wg": [
          {
            "ip": "173.245.78.142",
            "cn": "seattle402.privateinternetaccess.com"
          }
        ],
        "ovpntcp": [...],
        "ovpnudp": [...]
      }
    },
    ...
  ]
}
```

### What to Extract (for Seattle):
```javascript
const seattleRegion = response.regions.find(r => r.id === "us_seattle");

// For WireGuard connection, you need these two values:
const WG_SERVER_IP = seattleRegion.servers.wg[0].ip;        // e.g., "173.245.78.142"
const WG_HOSTNAME = seattleRegion.servers.wg[0].cn;         // e.g., "seattle402.privateinternetaccess.com"

// Optional - Check if port forwarding is supported:
const supportsPortForwarding = seattleRegion.port_forward;  // true for Seattle
```

### All US Regions You Can Choose From:
- `us_seattle` - US Seattle
- `us_california` - US California
- `us_new_york` - US New York
- `us_atlanta` - US Atlanta
- `us_chicago` - US Chicago
- `us_denver` - US Denver
- `us_houston` - US Houston
- `us_las_vegas` - US Las Vegas
- `us_phoenix` - US Phoenix
- `us_silicon_valley` - US Silicon Valley
- `us_washington_dc` - US Washington DC
- `us_east` - US East
- `us_west` - US West

---

## Step 3: Generate WireGuard Keys

**This happens locally - no API call**

WireGuard uses **Curve25519** (X25519) for key exchange. Keys are:
- **Private Key**: 32 random bytes, base64-encoded
- **Public Key**: Derived from private key using Curve25519, base64-encoded

### Method 1: Using WireGuard CLI Tools
```bash
# Generate private key
PRIVATE_KEY=$(wg genkey)

# Derive public key from private key
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
```

---

### Method 2: Using OpenSSL (v1.1.0+)

OpenSSL 1.1.0+ supports X25519 key generation.

#### Generate Keys:
```bash
# Generate private key (raw 32 bytes)
openssl genpkey -algorithm X25519 -out private.pem

# Extract raw private key bytes and base64 encode
openssl pkey -in private.pem -text -noout | \
  grep "priv:" -A 3 | tail -n 3 | \
  tr -d ' \n:' | xxd -r -p | base64

# Derive and extract public key
openssl pkey -in private.pem -pubout -out public.pem
openssl pkey -pubin -in public.pem -text -noout | \
  grep "pub:" -A 3 | tail -n 3 | \
  tr -d ' \n:' | xxd -r -p | base64
```

#### All-in-One Script:
```bash
#!/bin/bash

# Generate private key
openssl genpkey -algorithm X25519 -out /tmp/wg_private.pem 2>/dev/null

# Extract private key (32 bytes, base64 encoded)
PRIVATE_KEY=$(openssl pkey -in /tmp/wg_private.pem -text -noout | \
  grep "priv:" -A 3 | tail -n 3 | \
  tr -d ' \n:' | xxd -r -p | base64)

# Extract public key (32 bytes, base64 encoded)
PUBLIC_KEY=$(openssl pkey -in /tmp/wg_private.pem -text -noout | \
  grep "pub:" -A 3 | tail -n 3 | \
  tr -d ' \n:' | xxd -r -p | base64)

# Clean up
rm -f /tmp/wg_private.pem

echo "Private Key: $PRIVATE_KEY"
echo "Public Key:  $PUBLIC_KEY"
```

---

### Method 3: Using C# (.NET 6+)

C# can generate WireGuard keys using the `NSec` library or direct .NET crypto APIs.

#### Option A: Using NSec Library (Recommended)

NSec is a modern cryptographic library with built-in Curve25519 support.

**Install NuGet Package:**
```bash
dotnet add package NSec.Cryptography
```

**C# Code:**
```csharp
using System;
using NSec.Cryptography;

public class WireGuardKeyGenerator
{
    public static (string privateKey, string publicKey) GenerateKeys()
    {
        // Use X25519 algorithm (Curve25519 for key exchange)
        var algorithm = KeyAgreementAlgorithm.X25519;

        // Generate a new key pair
        using var key = Key.Create(algorithm, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });

        // Export private key (32 bytes)
        var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
        var privateKey = Convert.ToBase64String(privateKeyBytes);

        // Export public key (32 bytes)
        var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);
        var publicKey = Convert.ToBase64String(publicKeyBytes);

        return (privateKey, publicKey);
    }

    public static void Main()
    {
        var (privateKey, publicKey) = GenerateKeys();

        Console.WriteLine($"Private Key: {privateKey}");
        Console.WriteLine($"Public Key:  {publicKey}");
    }
}
```

#### Option B: Using .NET Cryptography (Manual Implementation)

If you can't use external libraries, use .NET's built-in crypto with manual Curve25519 computation.

**C# Code:**
```csharp
using System;
using System.Security.Cryptography;

public class WireGuardKeyGenerator
{
    // Note: .NET doesn't have built-in Curve25519, so we use ECDiffieHellman
    // with the X25519 curve (available in .NET 7+)
    public static (string privateKey, string publicKey) GenerateKeys()
    {
        // Create ECDiffieHellman instance with X25519 curve
        using var ecdh = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("X25519"));

        // Export private key
        var privateParams = ecdh.ExportParameters(true);
        var privateKeyBytes = privateParams.D; // D contains the private scalar
        var privateKey = Convert.ToBase64String(privateKeyBytes);

        // Export public key
        var publicParams = ecdh.ExportParameters(false);
        var publicKeyBytes = publicParams.Q.X; // X contains the public key
        var publicKey = Convert.ToBase64String(publicKeyBytes);

        return (privateKey, publicKey);
    }
}
```

**Note:** For .NET versions < 7, you'll need to use a library like **BouncyCastle**:

```csharp
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class WireGuardKeyGenerator
{
    public static (string privateKey, string publicKey) GenerateKeys()
    {
        // Initialize secure random generator
        var random = new SecureRandom();

        // Generate X25519 key pair
        var keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.Init(new X25519KeyGenerationParameters(random));
        var keyPair = keyPairGenerator.GenerateKeyPair();

        // Extract private key
        var privateKeyParam = (X25519PrivateKeyParameters)keyPair.Private;
        var privateKeyBytes = privateKeyParam.GetEncoded();
        var privateKey = Convert.ToBase64String(privateKeyBytes);

        // Extract public key
        var publicKeyParam = (X25519PublicKeyParameters)keyPair.Public;
        var publicKeyBytes = publicKeyParam.GetEncoded();
        var publicKey = Convert.ToBase64String(publicKeyBytes);

        return (privateKey, publicKey);
    }
}
```

**Install BouncyCastle:**
```bash
dotnet add package BouncyCastle.Cryptography
```

#### Complete C# Example (NSec):
```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;
using NSec.Cryptography;
using Newtonsoft.Json.Linq;

public class PIAWireGuardClient
{
    private readonly HttpClient _httpClient;

    public PIAWireGuardClient()
    {
        _httpClient = new HttpClient();
    }

    public async Task<string> GetAuthTokenAsync(string username, string password)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent(username), "username" },
            { new StringContent(password), "password" }
        };

        var response = await _httpClient.PostAsync(
            "https://www.privateinternetaccess.com/api/client/v2/token",
            content);

        var json = await response.Content.ReadAsStringAsync();
        var token = JObject.Parse(json)["token"].ToString();

        return token;
    }

    public (string privateKey, string publicKey) GenerateWireGuardKeys()
    {
        var algorithm = KeyAgreementAlgorithm.X25519;

        using var key = Key.Create(algorithm, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });

        var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
        var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);

        return (
            Convert.ToBase64String(privateKeyBytes),
            Convert.ToBase64String(publicKeyBytes)
        );
    }

    public async Task<JObject> RegisterWireGuardKeyAsync(
        string serverIp,
        string serverHostname,
        string token,
        string publicKey)
    {
        var url = $"https://{serverHostname}:1337/addKey?" +
                  $"pt={Uri.EscapeDataString(token)}&" +
                  $"pubkey={Uri.EscapeDataString(publicKey)}";

        // Note: You'll need to configure HttpClient to use the CA cert
        // and connect to the IP while validating against the hostname

        var response = await _httpClient.GetAsync(url);
        var json = await response.Content.ReadAsStringAsync();

        return JObject.Parse(json);
    }
}
```

---

### Example Keys (DO NOT USE THESE - generate your own):
```
Private: OLmY7Z7EpqGJZ9sYGKQT2kVvKRFqR4F3R3Z9Y7W9Y7E=
Public:  6B8CHk2KNqRFqR4F3R3Z9Y7W9Y7EGJQTOLmY7Z7EpqG=
```

---

### Key Generation Summary

| Method | Pros | Cons |
|--------|------|------|
| **WireGuard CLI** | Simple, guaranteed compatible | Requires WireGuard tools installed |
| **OpenSSL** | Available on most systems | Requires OpenSSL 1.1.0+ |
| **C# NSec** | Clean API, type-safe | External dependency |
| **C# .NET Native** | No dependencies (.NET 7+) | Newer .NET version required |
| **C# BouncyCastle** | Works on older .NET | Larger dependency |

---

## Step 4: Register Public Key with WireGuard Server

**Endpoint:** `https://{WG_HOSTNAME}:1337/addKey`
**Method:** GET with query parameters
**Authentication:** PIA Token from Step 1
**Certificate Validation:** REQUIRED - use ca.rsa.4096.crt

### curl Command:
```bash
curl -G \
  --connect-to "seattle402.privateinternetaccess.com::173.245.78.142:" \
  --cacert "ca.rsa.4096.crt" \
  --data-urlencode "pt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --data-urlencode "pubkey=6B8CHk2KNqRFqR4F3R3Z9Y7W9Y7EGJQTOLmY7Z7EpqG=" \
  "https://seattle402.privateinternetaccess.com:1337/addKey"
```

### Breaking Down the curl Command:

1. **`--connect-to "seattle402.privateinternetaccess.com::173.245.78.142:"`**
   - Forces curl to connect to the IP address while using the hostname for SSL verification
   - Format: `HOSTNAME::IP_ADDRESS:`

2. **`--cacert "ca.rsa.4096.crt"`**
   - Validates the server's SSL certificate against PIA's CA certificate
   - CRITICAL for security - don't skip this

3. **`--data-urlencode "pt=TOKEN"`**
   - `pt` = PIA Token from Step 1

4. **`--data-urlencode "pubkey=YOUR_PUBLIC_KEY"`**
   - Your generated WireGuard public key

### Response:
```json
{
  "status": "OK",
  "server_key": "UB8CHk2KNqRFqR4F3R3Z9Y7W9Y7EGJQTOLmY7Z7EpqG=",
  "server_port": 1337,
  "server_ip": "173.245.78.142",
  "server_vip": "10.0.0.1",
  "peer_ip": "10.13.37.42",
  "peer_pubkey": "6B8CHk2KNqRFqR4F3R3Z9Y7W9Y7EGJQTOLmY7Z7EpqG=",
  "dns_servers": [
    "10.0.0.242",
    "10.0.0.243"
  ]
}
```

### What to Extract:
```javascript
const config = {
  serverPublicKey: response.server_key,     // WireGuard server's public key
  serverPort: response.server_port,         // Usually 1337
  peerIP: response.peer_ip,                 // Your VPN IP address (10.x.x.x)
  dnsServers: response.dns_servers          // Optional PIA DNS servers
};
```

---

## Step 5: Create WireGuard Configuration

Using the data collected from previous steps, create a WireGuard config file.

### Configuration Template:
```ini
[Interface]
Address = 10.13.37.42                                    # peer_ip from Step 4
PrivateKey = OLmY7Z7EpqGJZ9sYGKQT2kVvKRFqR4F3R3Z9Y7W9Y7E=  # Your private key from Step 3
DNS = 10.0.0.242                                         # Optional: dns_servers[0] from Step 4

[Peer]
PublicKey = UB8CHk2KNqRFqR4F3R3Z9Y7W9Y7EGJQTOLmY7Z7EpqG=   # server_key from Step 4
AllowedIPs = 0.0.0.0/0                                   # Route all traffic through VPN
Endpoint = 173.245.78.142:1337                           # WG_SERVER_IP:server_port
PersistentKeepalive = 25                                 # Keep NAT mapping alive
```

### Save to File:
```bash
# Typically saved as:
/etc/wireguard/pia.conf
```

---

## Step 6: Connect to WireGuard

### Using wg-quick (recommended):
```bash
# Bring up the VPN interface
sudo wg-quick up pia

# Check status
sudo wg show

# Verify your IP changed
curl https://api.ipify.org

# Disconnect when done
sudo wg-quick down pia
```

### Using wg directly (advanced):
```bash
# Create interface
sudo ip link add dev wg0 type wireguard
sudo ip addr add 10.13.37.42/32 dev wg0

# Configure WireGuard
sudo wg setconf wg0 /etc/wireguard/pia.conf

# Bring up interface
sudo ip link set wg0 up

# Route all traffic through VPN
sudo ip route add default dev wg0
```

---

## Complete Example: Connect to Seattle

Here's a complete bash script showing all steps:

```bash
#!/bin/bash

# Configuration
PIA_USER="p0123456"
PIA_PASS="your_password"
REGION_ID="us_seattle"

# Step 1: Get Token
echo "Getting authentication token..."
TOKEN_RESPONSE=$(curl -s --request POST \
  'https://www.privateinternetaccess.com/api/client/v2/token' \
  --form "username=$PIA_USER" \
  --form "password=$PIA_PASS")
PIA_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
echo "Token: $PIA_TOKEN"

# Step 2: Get Server List
echo "Getting server list..."
SERVER_LIST=$(curl -s 'https://serverlist.piaservers.net/vpninfo/servers/v6')

# Step 3: Extract Seattle Server Info
echo "Extracting Seattle server info..."
WG_SERVER_IP=$(echo "$SERVER_LIST" | jq -r ".regions[] | select(.id==\"$REGION_ID\") | .servers.wg[0].ip")
WG_HOSTNAME=$(echo "$SERVER_LIST" | jq -r ".regions[] | select(.id==\"$REGION_ID\") | .servers.wg[0].cn")
echo "Server IP: $WG_SERVER_IP"
echo "Hostname: $WG_HOSTNAME"

# Step 4: Generate WireGuard Keys
echo "Generating WireGuard keys..."
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
echo "Public Key: $PUBLIC_KEY"

# Step 5: Register with WireGuard Server
echo "Registering with WireGuard server..."
WG_RESPONSE=$(curl -s -G \
  --connect-to "$WG_HOSTNAME::$WG_SERVER_IP:" \
  --cacert "ca.rsa.4096.crt" \
  --data-urlencode "pt=$PIA_TOKEN" \
  --data-urlencode "pubkey=$PUBLIC_KEY" \
  "https://$WG_HOSTNAME:1337/addKey")

# Check if registration was successful
STATUS=$(echo "$WG_RESPONSE" | jq -r '.status')
if [ "$STATUS" != "OK" ]; then
  echo "Error: Server returned $STATUS"
  exit 1
fi

# Extract configuration values
PEER_IP=$(echo "$WG_RESPONSE" | jq -r '.peer_ip')
SERVER_KEY=$(echo "$WG_RESPONSE" | jq -r '.server_key')
SERVER_PORT=$(echo "$WG_RESPONSE" | jq -r '.server_port')
DNS_SERVER=$(echo "$WG_RESPONSE" | jq -r '.dns_servers[0]')

echo "Peer IP: $PEER_IP"
echo "Server Port: $SERVER_PORT"

# Step 6: Create WireGuard Config
echo "Creating WireGuard configuration..."
cat > /etc/wireguard/pia.conf <<EOF
[Interface]
Address = $PEER_IP
PrivateKey = $PRIVATE_KEY
DNS = $DNS_SERVER

[Peer]
PublicKey = $SERVER_KEY
AllowedIPs = 0.0.0.0/0
Endpoint = $WG_SERVER_IP:$SERVER_PORT
PersistentKeepalive = 25
EOF

# Step 7: Connect
echo "Connecting to VPN..."
wg-quick up pia

echo "Connected! Your traffic is now routed through Seattle."
echo "To disconnect, run: wg-quick down pia"
```

---

## Simplified Pseudo-code for Your Application

```javascript
// 1. Authenticate
const token = await getAuthToken(username, password);

// 2. Get server info
const serverList = await getServerList();
const seattle = findRegion(serverList, "us_seattle");
const wgServer = seattle.servers.wg[0];

// 3. Generate keys
const { privateKey, publicKey } = generateWireGuardKeys();

// 4. Register with server
const wgConfig = await registerPublicKey({
  hostname: wgServer.cn,
  ip: wgServer.ip,
  token: token,
  publicKey: publicKey
});

// 5. Create config file
const configContent = createWireGuardConfig({
  peerIP: wgConfig.peer_ip,
  privateKey: privateKey,
  serverKey: wgConfig.server_key,
  serverIP: wgServer.ip,
  serverPort: wgConfig.server_port,
  dns: wgConfig.dns_servers[0]
});

// 6. Write config and connect
writeConfigFile("/etc/wireguard/pia.conf", configContent);
await executeCommand("wg-quick up pia");
```

---

## For Application-Level VPN Routing

If you want to route **only your application** through the VPN (not system-wide), you have a few options:

### Option 1: Use WireGuard with Policy-Based Routing
```bash
# Don't use AllowedIPs = 0.0.0.0/0
# Instead, specify only the IPs your app needs to reach
[Peer]
AllowedIPs = 203.0.113.0/24  # Only route specific destination IPs
```

### Option 2: Use Network Namespaces (Linux)
```bash
# Create isolated network namespace for your app
sudo ip netns add vpn
sudo ip link set wg0 netns vpn

# Run your app in the namespace
sudo ip netns exec vpn your-app
```

### Option 3: Use WireGuard in TUN Mode + Application Proxy
- Set up WireGuard interface without routing all traffic
- Use a SOCKS5 or HTTP proxy that routes through the WireGuard interface
- Configure your application to use that proxy

### Option 4: Use WireGuardNT (Windows)
On Windows with WireGuardNT, you can create a tunnel and bind your application's sockets to that specific interface.

---

## API Endpoints Summary

| Step | Endpoint | Method | Auth | Purpose |
|------|----------|--------|------|---------|
| 1 | `https://www.privateinternetaccess.com/api/client/v2/token` | POST | user/pass | Get 24h token |
| 2 | `https://serverlist.piaservers.net/vpninfo/servers/v6` | GET | None | List all servers |
| 3 | `https://{hostname}:1337/addKey` | GET | token | Register WG public key |

---

## Important Notes

1. **Token Expiration**: The authentication token expires after 24 hours. Cache it and regenerate when needed.

2. **SSL Certificate Validation**: Always validate against `ca.rsa.4096.crt`. This prevents MITM attacks.

3. **Ephemeral Keys**: Generate new WireGuard keys for each connection. Don't reuse them.

4. **Port Forwarding**: Seattle supports port forwarding (`port_forward: true`). If you need it, see `port_forwarding.sh` for the additional API calls.

5. **DNS Leaks**: Use PIA's DNS servers (`10.0.0.242`, `10.0.0.243`) or ensure your system DNS doesn't leak.

6. **IPv6**: PIA doesn't support IPv6. Disable it to prevent leaks:
   ```bash
   sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
   sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
   ```

7. **Server Selection**: Instead of hardcoding Seattle, you can test latency to multiple regions (see `get_region.sh` lines 103-121 for the latency testing logic).

---

## Testing Your Connection

After connecting, verify everything works:

```bash
# Check WireGuard status
sudo wg show

# Check your public IP (should be PIA's IP, not yours)
curl https://api.ipify.org

# Check for DNS leaks
curl https://www.dnsleaktest.com/

# Test connection to specific service
curl -v https://example.com
```

---

## Troubleshooting

### Connection Failed
- Verify token is valid (not expired)
- Check SSL certificate path is correct
- Ensure WireGuard tools are installed

### No Internet After Connecting
- Check if IPv6 is disabled
- Verify DNS settings in config
- Check firewall rules

### Slow Connection
- Try a different region
- Check server load (use latency testing)
- Verify no bandwidth limits on your account

---

## Additional Resources

- Original repo scripts: `./get_token.sh`, `./get_region.sh`, `./connect_to_wireguard_with_token.sh`
- PIA API documentation: https://github.com/pia-foss/manual-connections
- WireGuard documentation: https://www.wireguard.com/
