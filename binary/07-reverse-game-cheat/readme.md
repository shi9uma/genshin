# cheat-engine

学习各类游戏引擎的开发及其逆向工程，有助于更好理解反外挂行业，维护用户良好的体验。

市面上许多比较火的游戏都是基于 unity 开发的，例如英雄联盟、守望先锋、永劫无间、原神，下面主要介绍 unity 引擎下的外挂行为，思想是贯通的。

## implementation

>   数值系

一个最常见的工具就是 cheat engine

在游戏启动并装载后的内存中，找到血量（锁血）、魔法量（无限蓝）、金币数量（无限金币）、后座力（无后座）等内存位置，直接修改之即可；

同理，在引擎规定下，x、y、z 轴用于确定角色位置，改了 z 轴就能飞天遁地了

常用的数值修改系就称之为内存挂

>   规则系

透视。不同玩家对象都是会被装载到内存中的，每个对象都会有一个视角矩阵，通过计算对象的视角矩阵，计算出相对于自己，目标矩阵的具体坐标。

自瞄。锁定人物的骨骼位置，自己锁

瞬移。调游戏开发提供的传送函数，参数是目标地点的 xyz

内购。hook 掉支付模块的返回值

>   驱动挂

以上还只是各种手段在用户层修改游戏数据达到某些目的。高级一点的手段还有针对驱动编写驱动挂，通过驱动级编程，实现在内核态下对内存等数据区的操作。

驱动挂有更高的权限、更深层次的数据访问、更难以检测和持久性，毕竟反作弊软件一般运行于用户态。

## defense

一些第三方反作弊引擎有 TenProtect、Easy Anti Cheat、Valve Anti Cheat 等，常用的检测、反作弊思路有

-   文件、内存完整性校验：要魔改游戏文件以 hook 或装载一些额外功能，就必不可少要修改游戏的 dll、可执行文件等，校验文件完整性可以发现并拒绝游戏开始进程；还可以校验内存块的值，例如做双备份机制，对正在使用的内存计算 hash，再对备份了的、属于合法范围内的内存计算 hash，两者比较可觉察端倪
-   调试器检测、反调试器附加：游戏进程被调试就可以被认为正在被破解，检测到这些行为就根据常见的反调试行为来处理
-   混淆变量值：例如血量 hp_value 在内存中值为 100，可以对 hp_value 进行处理，例如减半用 50 表示，这样在面对 cheat engine 这类检索内存值时可以有效提高破解难度
-   检测各种 dll 注入行为

有的反作弊引擎除了对游戏进行反作弊检测，还喜欢扫描用户的硬盘文件。美其名曰检测到可疑文件上报以提高反作弊效率，实际上就是在侵犯隐私，这类引擎在欧盟那边容易因为侵犯用户权益吃官司。

## test-01

介绍 cheat-engine 简单做个测试，游戏是 Plants vs. Zombies

1.   打开一局游戏，正常进入流程

2.   启动 cheat engine，对 pvz.exe 附加，搜索阳光值，修改阳光值，找到阳光值对应的内存地址，右键 "找出是什么改写了这个地址"，再次修改阳光值，找到地址 `0x41F4D0`，同时可以确定当前阳光存放地址为 `0x1B2BFF00 + 0x5578 = 0x1B2C5478`

     ![image-20240228160055557](E:\Pictures\markdown\image-20240228160055557.png)

3.   右键 "在反汇编程序中显示地址"，观察阳光值修改逻辑

     ![image-20240228160302225](E:\Pictures\markdown\image-20240228160302225.png)

4.   **工具 - 自动汇编 - 模板 - 代码注入**，主要将 `add [eax+00005578], ecx` 修改成 `mov [eax+00005578], 2706`，即直接将阳光值修改成 0x2706；修改完成后 **模板 - CT 表框架代码** 制作常驻脚本；**文件 - 分配到当前 CT 表**

     ![image-20240228160634225](E:\Pictures\markdown\image-20240228160634225.png)

5.   点击执行后，cheat engine 自动采用一个飞线的形式，将原来 `0x401F4D0` 汇编修改成 `jmp ex_addr`，在飞地完成 `mov [eax+00005578], 2706` 后，再 `jmp ` 回原来的 eip，且自动堆栈平衡

     ![image-20240228160935284](E:\Pictures\markdown\image-20240228160935284.png)

6.   保存这个 ct 脚本，后续直接点击即可注入代码，实现无限阳光

## test-02

