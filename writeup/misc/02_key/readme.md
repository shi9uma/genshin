## key

拿到 png 图片，查看基础信息：

```bash
┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/key]
└─$ file key.jpg
key.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 0x0, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=1]

┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/key]
└─$ binwalk -e key.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
1801          0x709           Copyright string: "Copyright Apple Inc., 2023"
272587        0x428CB         Zip archive data, at least v2.0 to extract, uncompressed size: 32, name: flag.enc
272794        0x4299A         End of Zip archive, footer length: 22


┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/key]
└─$ ls _key.jpg.extracted
428CB.zip  flag.enc

┌──(wkyuu㉿kali)-[/c/…/wkyuu/Desktop/20240425/key]
└─$ cat flag.enc
_7��OU�0C��O�?Q�s�2��;�J
                        F�
```

附件只有 jpg 文件一个，因此需要到图片中寻找具体信息，

![image-20240425180214179](E:\Pictures\markdown\image-20240425180214179.png)

有 e 和模数 n，可以得到以下信息

```bash
e = 65537

n = p * q = 58239180654929120650500449428917292711228851865043992721378668316322123829843 = 0x80C23546F66C490FAB718322666B3AD9C5D31C4D4BDA4C1D783FC73FB4115253
```

这个很好解决，使用 yafu 在后台跑就可以：

```bash
PS C:\Users\wkyuu\Desktop\20240425\key> .\yafu-x64.exe "factor(58239180654929120650500449428917292711228851865043992721378668316322123829843)"

fac: factoring 58239180654929120650500449428917292711228851865043992721378668316322123829843
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits
div: primes less than 10000
fmt: 1000000 iterations
rho: x^2 + 3, starting 1000 iterations on C77
rho: x^2 + 2, starting 1000 iterations on C77
rho: x^2 + 1, starting 1000 iterations on C77
pm1: starting B1 = 150K, B2 = gmp-ecm default on C77
ecm: 30/30 curves on C77, B1=2K, B2=gmp-ecm default
ecm: 74/74 curves on C77, B1=11K, B2=gmp-ecm default
ecm: 149/149 curves on C77, B1=50K, B2=gmp-ecm default, ETA: 0 sec

starting SIQS on c77: 58239180654929120650500449428917292711228851865043992721378668316322123829843

==== sieving in progress (1 thread):   36224 relations needed ====
====           Press ctrl-c to abort and save state           ====
36334 rels found: 18009 full + 18325 from 193520 partial, (2383.12 rels/sec)

SIQS elapsed time = 90.0596 seconds.
Total factoring time = 102.7176 seconds


***factors found***

P39 = 336864880216429367305541498622715085359
P39 = 172885878211796787522220685199694830877

ans = 1
```

得到结果 p 和 q，并且提取加密数据：

![image-20240425180403335](E:\Pictures\markdown\image-20240425180403335.png)

最终得到的信息如下

```python
e = 65537

p = 336864880216429367305541498622715085359
q = 172885878211796787522220685199694830877

n = p * q = 58239180654929120650500449428917292711228851865043992721378668316322123829843 = 0x80C23546F66C490FAB718322666B3AD9C5D31C4D4BDA4C1D783FC73FB4115253

enc_hex = 115F379D944F55823043AA824FF13F51BA73E632B4F93BE44A0C467FE51B25B4
```

简单写一个 python 脚本如下

```python
# -*- coding: utf-8 -*-
from sympy import mod_inverse

e = 65537
p = 336864880216429367305541498622715085359
q = 172885878211796787522220685199694830877

n = p * q
phi_n = (p - 1) * (q - 1)  # 计算欧拉数
d = mod_inverse(e, phi_n)  # 模逆

with open('flag.enc', 'rb') as file:	# r 报错
    enc_bin = file.read()

enc_hex = enc_bin.hex()
enc_int = int(enc_hex, 16)
decrypted_int = pow(enc_int, d, n)

decrypted_hex = hex(decrypted_int)[2:]
if len(decrypted_hex) % 2 != 0:	# 不为偶数会报错
    decrypted_hex = '0' + decrypted_hex
decrypted_text = bytes.fromhex(decrypted_hex).decode('utf-8', errors='replace')

print(decrypted_text)
```

运行之：

```bash
(data_venv) PS C:\Users\wkyuu\Desktop\20240425\key> python .\key.py
2�Ia�4D�flag{ed22321e9ae1ca8}
```

