## 前言
这道题做了超久，大概断断续续四天。准备逆向之前一定要有充足的精力再开始。逆向的时候可以从正向的角度想想，如果要实现这个功能，这个参数的意思是什么。比如idb中的operator参数和array100参数是分别用来存放运算符和数字的。废话不多说，再来分析一下此题。详细的WP可以参考[1]。

## 思路
利用数组越界漏洞，完成任意读写。  

```
理解其实感觉很绕 多看几遍，本质是*array100不再是2了。
IDA中array100[*array100 - 1] += array100[*array100];

若 1+1
array100[0] = 2 array100[1] = 1 array100[2] = 1
operator[0] = +
then
*array100 = 2
array100[1] = 2

若 +300
array100[0] = 1 array100[1] = 300
operator[0] = +
then
array100[*array100 - 1] += array100[*array100];
*array100 = 1
array100[0] += array100[300]
```

- 读："+ offset" 读取 array100 offset处的值。比如ebp距离array100的距离是360*4，那么读取ebp输入+360即可，假设值为raw。
- 写：读之后，若写入的值是value，T=value-raw。T>0，利用"+361+T"写。
否则用"+361+T"写。（T此时为负）若value很大，0xffxxxxxx，可以先将value-0x100000000，两者值相等。


任意读写之后，由于开启了NX，修改返回地址并布置rop即可调用execve('/bin/sh'，0，0)getshell。由于源程序中没有/bin/sh，因此可以收工将字符串布置在栈上，读ebp中保存的值来计算偏移。

**注**

- u32(str)，str是一个4byte的字符串。  
- system("sh")也可以，但是execve只能执行"/bin/sh"。



## Reference
[1] <http://www.freebuf.com/articles/others-articles/132283.html>  
[2] <http://dogewatch.github.io/2017/04/10/pwnable.tw-Part1/>

