**[CISCN 2022 东北]easycpp**

考点：伪C阅读，异或

解题思路和过程：

下载附件，无壳64位，拖IDA，发现去符号了，而且字符串一眼没看见有效信息，运行一下，打印了Wrong，搜一下Wrong，来到了main。

< img src="1.png" width="50%">
< img src="2.png" width="50%">

一步一步看一下，不清楚这个凭空出现的Src是什么，交叉引用一下，发现sub_140002B60也同样把输入存进Src里了。

< img src="3.png" width="50%">
< img src="4.png" width="50%">

剩下就很清晰了，注释了一下，提炼成三个异或。

< img src="5.png" width="50%">
< img src="6.png" width="50%">

看到 memcmp(内存比较)，于是顺着找密文(v12=Buf2)，但点进 Buf2 只发现了占位符，看来是动态拷进来的。交叉引用一下，来到一开始的 UP(而不是 Down，靠后的一般是在清空数据)，发现了密文。

可以写脚本了，解密脚本如下：

```python
data = [
    0x0A, 0x0B, 0x7D, 0x2F, 0x7F, 0x67, 0x65, 0x30, 0x63, 0x60,
    0x37, 0x3F, 0x3C, 0x3F, 0x33, 0x3A, 0x3C, 0x3B, 0x35, 0x3C,
    0x3E, 0x6C, 0x64, 0x31, 0x64, 0x6C, 0x3B, 0x68, 0x61, 0x62,
    0x65, 0x36, 0x33, 0x60, 0x62, 0x36, 0x1C, 0x7D
]

for i in range(len(data) - 4, -1, -1):
    data[i + 2] ^= data[i + 3]
    data[i + 1] ^= data[i + 2]
    data[i] ^= data[i + 1]

print(data)
for j in range(len(data)):
    print(chr(data[j]), end="")