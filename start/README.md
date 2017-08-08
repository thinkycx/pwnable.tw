思路：第一次利用bof ret到sys_write处，泄漏栈的地址。第二次读入shellcode，计算偏移跳转执行。

程序的主要功能有两个：    
1. 用`sys_write`[系统调用](http://syscalls.kernelgrok.com/)输出一段字符串  
2. 后用`sys_read`获取输入  
3. retn调用`_exit`退出程序  

本题奇怪的地方在于程序开始时首先`push esp`再`push _exit`函数的地址，导致`retn`后`esp`指向了栈的地址。
在sys_read处存在bof有一次布置shellcode和控制EIP的机会。本题的难点在于如何确定shellcode的地址。

再回到程序的功能本身，只有一次读，一次写，一次退出。如果要在栈上shellcode，必须要知道栈的地址。而栈的地址在程序`retn`后保存在了`esp`中。我们可以控制`EIP`为`0x8048087`,利用程序本身的`sys_write`读来泄漏栈的地址。

生成shellcode两种利用方式：

- 一种根据esp的之计算shellcode的起始地址,布置shellcode即可.(别人写好的shellcode)
- 一种手写shelcode asm转化成汇编之后布置即可,两种方法其实是一样的,只是用来尝试一下手写shellcode而已.