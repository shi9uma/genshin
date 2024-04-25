## seeyouagain

拿到附件，是一个 flag.png，打不开

![image-20240425165353650](E:\Pictures\markdown\image-20240425165353650.png)

获取基础信息：

```bash
┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/seeyouagain]
└─$ file flag.png
flag.png: PNG image data, 1372 x 555, 8-bit/color RGBA, non-interlaced

┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/seeyouagain]
└─$ binwalk -e flag.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1372 x 555, 8-bit/color RGBA, non-interlaced
3269          0xCC5           TIFF image data, big-endian, offset of first image directory: 8
3337          0xD09           Zlib compressed data, compressed
800590        0xC374E         Zip archive data, encrypted compressed size: 1149, uncompressed size: 5099, name: flag.txt
801889        0xC3C61         End of Zip archive, footer length: 22

┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/seeyouagain]
└─$ ls _flag.png.extracted
C374E.zip  D09  D09.zlib
```

拿到一个加密的压缩包文件，然后尝试从 png 文件里找信息，使用 `pngcheck flag.png` 检查文件属性：

```bash
┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/seeyouagain]
└─$ pngcheck flag.png
zlib warning:  different version (expected 1.2.13, using 1.3)

flag.png  CRC error in chunk IHDR (computed 1300524a, expected 25c41629)
ERROR: flag.png
```

表示该文件的 IHDR 数据库的 crc 校验和出错，IHDR 包含了 png 图片的基本信息，因此需要将其修复，使用 [feresg/RITSEC-CTF](https://github.com/feresg/RITSEC-CTF.git) 中的 pngcsum 工具修复之：

```bash
┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/seeyouagain]
└─$ ./pngcsum flag.png fix_flag.png
IHDR ( 13 ) - csum = 25c41629 -> 1300524a
gAMA (  4 ) - csum = 7cfb5193
cHRM ( 32 ) - csum = 91df48de
iCCP (3135 ) - csum = 618ba020
pHYs (  9 ) - csum = 8fe5f165
eXIf ( 56 ) - csum = c61c5bc1
IDAT (62199 ) - csum = 331586ff
IDAT (65524 ) - csum = 234777ea
IDAT (65524 ) - csum = ead89c2b
IDAT (65524 ) - csum = 1678638a
IDAT (65524 ) - csum = ba23607c
IDAT (65524 ) - csum = d1f61c99
IDAT (65524 ) - csum = 008dffa0
IDAT (65524 ) - csum = cf5ade93
IDAT (65524 ) - csum = 430bb376
IDAT (65524 ) - csum = f3320dfa
IDAT (65524 ) - csum = f42125d6
IDAT (65524 ) - csum = 5bd38a89
IDAT (14130 ) - csum = 687e0cee
IEND (  0 ) - csum = ae426082
```

此时可以正常打开，目前没有看到什么有效的信息，包括使用 slienteye 等工具都没有比较有效的信息

尝试比较原始的使用 winhex 打开，尝试修改其 width 和 height，

![image-20240425171118380](E:\Pictures\markdown\image-20240425171118380.png)

修改成 `00 00 05 5c 00 00 05 5c`，然后修复之：` ./pngcsum fix_flag.png 2fix_flag.png`，得到 zip 压缩包密码

![image-20240425171401510](E:\Pictures\markdown\image-20240425171401510.png)

将其解压得到很多 base64 编码内容，使用 cyberchef 解码

![image-20240425171505294](E:\Pictures\markdown\image-20240425171505294.png)

出现了一些不和谐的东西，因此猜测为 [base64 隐写](https://www.tr0y.wang/2017/06/14/Base64steg/)，相关脚本如下：

```python
import base64
def get_diff(s1, s2):
    base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = 0
    for i in range(len(s2)):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return res

def b64_stego_decode():
    file = open("a/flag.txt","rb")
    x = ''
    lines =  file.readlines()
    for line in lines:
        l = str(line, encoding = "utf-8")
        stego = l.replace('\n','')
        realtext = base64.b64decode(l)
        realtext = str(base64.b64encode(realtext),encoding = "utf-8")
        diff = get_diff(stego, realtext)
        n = stego.count('=')
        if diff:
            x += bin(diff)[2:].zfill(n*2)
        else:
            x += '0' * n*2
            
    i = 0
    flag = ''
    while i < len(x):
        if int(x[i:i+8],2):
            flag += chr(int(x[i:i+8],2))
        i += 8
    print(flag)

if __name__ == '__main__':
    b64_stego_decode()
```

得到 flag：`flag{da6ac101b05b6974}`

ps：base64 隐写的逆向简单来说就是，将 base64 解码后再重新编码，获取标准的 base64 编码字符串，比较其与原始行的内容，**计算差异值**，根据行尾的等号数量（base64 编码中的填充内容），将这些差异值转换为二进制，拼接并输出就是最后的 flag