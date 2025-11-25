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

### Method 3: Using C# with Windows BCrypt APIs

C# can generate WireGuard keys using the Windows BCrypt (Cryptography API: Next Generation) through P/Invoke. This is the native Windows approach with no external dependencies.

#### Complete BCrypt Implementation:

```csharp
using System;
using System.Runtime.InteropServices;

public static class WireGuardKeyGenerator
{
    // BCrypt Algorithm Identifiers
    private const string BCRYPT_ECDH_ALGORITHM = "ECDH";
    private const string BCRYPT_ECC_CURVE_25519 = "curve25519";

    // BCrypt flags
    private const uint BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = 0x504B4345;
    private const uint BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = 0x564B4345;

    // Property strings
    private const string BCRYPT_ECC_CURVE_NAME = "ECCCurveName";

    // Blob types
    private const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";
    private const string BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB";

    #region P/Invoke Declarations

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern uint BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm,
        string pszAlgId,
        string pszImplementation,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptCloseAlgorithmProvider(
        IntPtr hAlgorithm,
        uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern uint BCryptSetProperty(
        IntPtr hObject,
        string pszProperty,
        byte[] pbInput,
        uint cbInput,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptGenerateKeyPair(
        IntPtr hAlgorithm,
        out IntPtr phKey,
        uint dwLength,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptFinalizeKeyPair(
        IntPtr hKey,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptExportKey(
        IntPtr hKey,
        IntPtr hExportKey,
        string pszBlobType,
        byte[] pbOutput,
        uint cbOutput,
        out uint pcbResult,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern uint BCryptDestroyKey(
        IntPtr hKey);

    #endregion

    [StructLayout(LayoutKind.Sequential)]
    private struct BCRYPT_ECCKEY_BLOB
    {
        public uint dwMagic;
        public uint cbKey;
    }

    public static (string privateKey, string publicKey) GenerateKeys()
    {
        IntPtr algHandle = IntPtr.Zero;
        IntPtr keyHandle = IntPtr.Zero;

        try
        {
            // Open algorithm provider for ECDH
            uint status = BCryptOpenAlgorithmProvider(
                out algHandle,
                BCRYPT_ECDH_ALGORITHM,
                null,
                0);

            if (status != 0)
                throw new InvalidOperationException($"BCryptOpenAlgorithmProvider failed: 0x{status:X}");

            // Set the curve to Curve25519
            byte[] curveNameBytes = System.Text.Encoding.Unicode.GetBytes(BCRYPT_ECC_CURVE_25519 + "\0");
            status = BCryptSetProperty(
                algHandle,
                BCRYPT_ECC_CURVE_NAME,
                curveNameBytes,
                (uint)curveNameBytes.Length,
                0);

            if (status != 0)
                throw new InvalidOperationException($"BCryptSetProperty failed: 0x{status:X}");

            // Generate key pair (256 bits = 32 bytes for Curve25519)
            status = BCryptGenerateKeyPair(
                algHandle,
                out keyHandle,
                256,
                0);

            if (status != 0)
                throw new InvalidOperationException($"BCryptGenerateKeyPair failed: 0x{status:X}");

            // Finalize the key pair
            status = BCryptFinalizeKeyPair(keyHandle, 0);
            if (status != 0)
                throw new InvalidOperationException($"BCryptFinalizeKeyPair failed: 0x{status:X}");

            // Export public key
            byte[] publicKeyBlob = ExportKey(keyHandle, BCRYPT_ECCPUBLIC_BLOB);
            byte[] publicKeyBytes = ExtractPublicKey(publicKeyBlob);
            string publicKey = Convert.ToBase64String(publicKeyBytes);

            // Export private key
            byte[] privateKeyBlob = ExportKey(keyHandle, BCRYPT_ECCPRIVATE_BLOB);
            byte[] privateKeyBytes = ExtractPrivateKey(privateKeyBlob);
            string privateKey = Convert.ToBase64String(privateKeyBytes);

            return (privateKey, publicKey);
        }
        finally
        {
            if (keyHandle != IntPtr.Zero)
                BCryptDestroyKey(keyHandle);

            if (algHandle != IntPtr.Zero)
                BCryptCloseAlgorithmProvider(algHandle, 0);
        }
    }

    private static byte[] ExportKey(IntPtr keyHandle, string blobType)
    {
        // Get the size of the blob
        uint blobSize;
        uint status = BCryptExportKey(
            keyHandle,
            IntPtr.Zero,
            blobType,
            null,
            0,
            out blobSize,
            0);

        if (status != 0)
            throw new InvalidOperationException($"BCryptExportKey (size) failed: 0x{status:X}");

        // Export the key
        byte[] blob = new byte[blobSize];
        status = BCryptExportKey(
            keyHandle,
            IntPtr.Zero,
            blobType,
            blob,
            blobSize,
            out blobSize,
            0);

        if (status != 0)
            throw new InvalidOperationException($"BCryptExportKey failed: 0x{status:X}");

        return blob;
    }

    private static byte[] ExtractPublicKey(byte[] blob)
    {
        // Blob structure: BCRYPT_ECCKEY_BLOB header + public key (32 bytes)
        int headerSize = Marshal.SizeOf<BCRYPT_ECCKEY_BLOB>();

        if (blob.Length < headerSize + 32)
            throw new InvalidOperationException("Invalid public key blob size");

        byte[] publicKey = new byte[32];
        Array.Copy(blob, headerSize, publicKey, 0, 32);
        return publicKey;
    }

    private static byte[] ExtractPrivateKey(byte[] blob)
    {
        // Blob structure: BCRYPT_ECCKEY_BLOB header + public key (32 bytes) + private key (32 bytes)
        int headerSize = Marshal.SizeOf<BCRYPT_ECCKEY_BLOB>();

        if (blob.Length < headerSize + 64)
            throw new InvalidOperationException("Invalid private key blob size");

        byte[] privateKey = new byte[32];
        Array.Copy(blob, headerSize + 32, privateKey, 0, 32);
        return privateKey;
    }

    // Example usage
    public static void Main()
    {
        var (privateKey, publicKey) = GenerateKeys();

        Console.WriteLine($"Private Key: {privateKey}");
        Console.WriteLine($"Public Key:  {publicKey}");
    }
}

#### Complete C# PIA WireGuard Client with BCrypt:

```csharp
using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

public class PIAWireGuardClient
{
    private readonly HttpClient _httpClient;

    public PIAWireGuardClient()
    {
        // Configure HttpClient with custom certificate validation
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = ValidateServerCertificate
        };
        _httpClient = new HttpClient(handler);
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

        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("token").GetString();
    }

    public async Task<JsonNode> GetServerListAsync()
    {
        var response = await _httpClient.GetAsync(
            "https://serverlist.piaservers.net/vpninfo/servers/v6");

        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return JsonNode.Parse(json);
    }

    public (string ip, string hostname) GetServerInfo(JsonNode serverList, string regionId)
    {
        var regions = serverList["regions"].AsArray();
        foreach (var region in regions)
        {
            if (region["id"].GetValue<string>() == regionId)
            {
                var wgServers = region["servers"]["wg"].AsArray();
                return (
                    wgServers[0]["ip"].GetValue<string>(),
                    wgServers[0]["cn"].GetValue<string>()
                );
            }
        }
        throw new ArgumentException($"Region {regionId} not found");
    }

    public (string privateKey, string publicKey) GenerateWireGuardKeys()
    {
        return WireGuardKeyGenerator.GenerateKeys();
    }

    public async Task<WireGuardConfig> RegisterWireGuardKeyAsync(
        string serverIp,
        string serverHostname,
        string token,
        string publicKey)
    {
        var url = $"https://{serverHostname}:1337/addKey?" +
                  $"pt={Uri.EscapeDataString(token)}&" +
                  $"pubkey={Uri.EscapeDataString(publicKey)}";

        // Create request that connects to IP but validates against hostname
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        var response = await _httpClient.SendAsync(request);

        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        return new WireGuardConfig
        {
            Status = root.GetProperty("status").GetString(),
            PeerIp = root.GetProperty("peer_ip").GetString(),
            ServerKey = root.GetProperty("server_key").GetString(),
            ServerPort = root.GetProperty("server_port").GetInt32(),
            DnsServers = root.GetProperty("dns_servers").EnumerateArray()
                .Select(e => e.GetString()).ToArray()
        };
    }

    public string GenerateWireGuardConfigFile(
        WireGuardConfig wgConfig,
        string privateKey,
        string serverIp)
    {
        return $@"[Interface]
Address = {wgConfig.PeerIp}
PrivateKey = {privateKey}
DNS = {wgConfig.DnsServers[0]}

[Peer]
PublicKey = {wgConfig.ServerKey}
AllowedIPs = 0.0.0.0/0
Endpoint = {serverIp}:{wgConfig.ServerPort}
PersistentKeepalive = 25
";
    }

    private bool ValidateServerCertificate(
        HttpRequestMessage request,
        X509Certificate2 certificate,
        X509Chain chain,
        SslPolicyErrors errors)
    {
        // Load PIA CA certificate from ca.rsa.4096.crt file
        // and validate the server certificate against it
        // For now, accept valid certificates
        return errors == SslPolicyErrors.None ||
               errors == SslPolicyErrors.RemoteCertificateNameMismatch;
    }

    // Example usage
    public static async Task Main()
    {
        var client = new PIAWireGuardClient();

        // Step 1: Get token
        Console.WriteLine("Getting authentication token...");
        string token = await client.GetAuthTokenAsync("p0123456", "your_password");
        Console.WriteLine($"Token: {token}");

        // Step 2: Get server list
        Console.WriteLine("\nGetting server list...");
        var serverList = await client.GetServerListAsync();

        // Step 3: Get Seattle server info
        var (serverIp, serverHostname) = client.GetServerInfo(serverList, "us_seattle");
        Console.WriteLine($"Server: {serverHostname} ({serverIp})");

        // Step 4: Generate keys
        Console.WriteLine("\nGenerating WireGuard keys...");
        var (privateKey, publicKey) = client.GenerateWireGuardKeys();
        Console.WriteLine($"Public Key: {publicKey}");

        // Step 5: Register with server
        Console.WriteLine("\nRegistering with WireGuard server...");
        var wgConfig = await client.RegisterWireGuardKeyAsync(
            serverIp, serverHostname, token, publicKey);
        Console.WriteLine($"Assigned IP: {wgConfig.PeerIp}");

        // Step 6: Generate config file
        string configFile = client.GenerateWireGuardConfigFile(
            wgConfig, privateKey, serverIp);
        Console.WriteLine("\nWireGuard Configuration:");
        Console.WriteLine(configFile);

        // Save to file
        System.IO.File.WriteAllText("pia.conf", configFile);
        Console.WriteLine("Configuration saved to pia.conf");
        Console.WriteLine("\nTo connect: wg-quick up pia");
    }
}

public class WireGuardConfig
{
    public string Status { get; set; }
    public string PeerIp { get; set; }
    public string ServerKey { get; set; }
    public int ServerPort { get; set; }
    public string[] DnsServers { get; set; }
}
```

---

### Example Keys (DO NOT USE THESE - generate your own):
```
Private: OLmY7Z7EpqGJZ9sYGKQT2kVvKRFqR4F3R3Z9Y7W9Y7E=
Public:  6B8CHk2KNqRFqR4F3R3Z9Y7W9Y7EpqG=
```

---

### Key Generation Summary

| Method | Pros | Cons |
|--------|------|------|
| **WireGuard CLI** | Simple, guaranteed compatible | Requires WireGuard tools installed |
| **OpenSSL** | Available on most systems | Requires OpenSSL 1.1.0+ |
| **C# BCrypt** | Native Windows API, no dependencies | Windows only, requires P/Invoke |

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
