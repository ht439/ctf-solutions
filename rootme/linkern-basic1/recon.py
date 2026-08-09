from pwn import *

HOST = "challenge03.root-me.org"
PORT = 2223
USER = "app-systeme-ch1"
PASSWORD = "app-systeme-ch1"

context.log_level = "info"

s = ssh(
    host=HOST,
    port=PORT,
    user=USER,
    password=PASSWORD,
)

p = s.run("./run")
p.recvuntil(b"Welcome to this kernel exploitation challenge!", timeout=30)

print("\n[+] VM booted\n")

sleep(1)

commands = [
    "echo __READY__",
    "id",
    "uname -a",
    "ls -l /dev/tostring",
    "cat /proc/devices",
    "grep -E ' (prepare_kernel_cred|commit_creds)$' /proc/kallsyms",
    "cat /proc/sys/kernel/randomize_va_space",
]

for cmd in commands:
    print(f"\n===== {cmd} =====")
    p.sendline(cmd.encode())

    out = p.recvrepeat(1)
    print(out.decode(errors="replace"))

s.close()
