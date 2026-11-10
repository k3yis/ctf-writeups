**ctfshow reverse re2**

考点：标准 RC4，异或

解题过程和思路：
下载附件，是一个密文(内容是乱码)和一个exe。然而exe并没有病毒，虚惊一场，打印了几行中文，无壳，32位控制台

< img src="1.png" width="50%">

< img src="2.png" width="50%">

拖进IDA，先看字符串，发现一串密文，暂时不知道有什么作用，先放着。函数没有去符号，打开main看看。每行注释了一下便于分析

< img src="3.png" width="50%">

< img src="4.png" width="50%">

可以轻松(?得知第52行很可疑，进去看看，发现了四个函数，挨个点开看看。初步判断是RC4，因为满屏256和%256，还有三变量交换，甚至最后也是异或。再仔细看看有没有魔改。

< img src="5.png" width="50%">

第一个函数：提前制作超长密钥，为后面的状态更新变量j的制作作铺垫，但不是魔改，只是让cpu在后面不用对key做那么多取模运算来从头取key的字符，直接安心遍历。

< img src="6.png" width="50%">

第二个函数，纯粹的S盒初始化

< img src="7.png" width="50%">

第三个函数，经典三变量交换

< img src="8.png" width="50%">

第四个函数，开始生成密钥流和逐字符加密了，没有魔改。

< img src="9.png" width="50%">

既然知道是RC4了，一开始进IDA门见到的字符串肯定和密钥有关，根据逻辑异或一下得到key，是 `[Warnning]Access_Unauthorized`，脚本比较简单，不赘述了。

< img src="10.png" width="50%">

附上标准RC4脚本，使用时注意检查RC4是否被魔改，手动修改代码：

```python
def rc4_custom(data: bytes, key: bytes, s_len=256, magic_xor=0):
    S = list(range(s_len))
    j = 0
    key_len = len(key)

    for i in range(s_len):
        j = (j + S[i] + key[i % key_len]) % s_len
        S[i], S[j] = S[j], S[i]

    out = bytearray()
    i = 0
    j = 0

    for char in data:
        i = (i + 1) % s_len
        j = (j + S[i]) % s_len
        S[i], S[j] = S[j], S[i]

        K = S[(S[i] + S[j]) % s_len]
        decrypted_char = char ^ K ^ magic_xor
        out.append(decrypted_char)

    return bytes(out)

if __name__ == '__main__':
    with open('enflag.txt', 'rb') as f:
        ciphertext = f.read()
    
    key = b"[Warnning]Access_Unauthorized"

    try:
        plaintext = rc4_custom(ciphertext, key)

        print("解密结果 (字符串):", plaintext.decode('utf-8', errors='ignore'))
        print("解密结果 (十六进制):", plaintext.hex())
    except Exception as e:
        print("解密报错，检查密文或 Key 格式以及RC4是否标准: ", e)