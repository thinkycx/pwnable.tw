## Refs
1. <http://www.freebuf.com/articles/others-articles/134271.html>

## 思路
```
  unsigned int number; // [sp+18h] [bp-74h]@1
  int numbers; // [sp+1Ch] [bp-70h]@2
  int name; // [sp+3Ch] [bp-50h]@1
  int v12; // [sp+7Ch] [bp-10h]@1
```
保护机制全开，漏洞的原因是利用scanf("%u",&a)读取numbers，并排序，数字的数量没有限制，导致栈溢出。如果a为+ - ，则依然原来的值。如果a为字母，则scanf从此之后都失败。  

利用scanf("%s",&name);泄漏stack中程序的.text段地址，根据偏移计算main_addr。构造numbers输入，维护canary，泄漏ebp之前libc中的地址，根据偏移计算libc_addr,同时覆盖返回地址为main_addr。下一次输入，维护canary，构造ret2libc拿shell。

## 分析
1. 栈中libc的地址和libc_addr之间的偏移和libc.so有关系。计算offset后，readelf -S libc.so可以offset处的name，根据name到新libc中寻找新offset。
2. scanf("%u"，&a);读取的是数字，因此直接把十进制数转化成字符串输入就好。此外读取+ ，- 为什么不会替换原来的值，尚不清楚。
3. IDA F5分析可能不准确，看汇编验证自己的想法。比如本题都是根据esp来计算定位参数的。
4. info sharedlibrary查看的是elf加载时，so text节的地址，vmmap（ldd）查看的是整个so文件的地址。
5. 本题我采用的是先利用读取name来泄漏main的地址，再sort泄漏libc的地址。第二次执行main 利用ret2libc拿shell。其实也可以在第一次读取name时候泄漏libc的地址，那么可以直接在sort时拿shell。这样有个好处，libc的地址通常很大，可以布置在后面没问题。第一种方法，泄漏main的地址，要求canary比main小，可能需要多次执行。
6. 熬夜做题不好，下次再也不熬夜了。
