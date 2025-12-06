#!/usr/bin/env python3
"""
RSC Master Exploit Tool
Entry point for the rsc_exploit package.
"""
import sys
from rsc_exploit.cli import main

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")
        sys.exit(0)