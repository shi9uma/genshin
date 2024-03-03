# introduction

逆向工程，reverse engineering，猜测和分析已有项目的运行逻辑，按照目的而作出违反原程序既定逻辑的行为

在逆向工程的实际应用中，可以举例以下情况：

-   设计一套病毒、木马，需要逃过靶机上的安全审查；对应的进行病毒样本的逆向来编写查杀脚本
-   破解软件，制作外挂；对应反破解，外挂检测
-   漏洞挖掘；对应漏洞检测和修复
-   ....

## tools

逆向工程常用的一些工具

1.   静态
     1.   **ida**，[IDA Pro](https://hex-rays.com/ida-pro/)；对二进制文件进行反汇编和静态分析，提供直观的图形界面和强大的反汇编功能，用于理解程序的结构和逻辑
     2.   **ghidra**，[NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra.git)；由美国国家安全局（NSA）开发的开源逆向工程框架，支持多平台，用于反汇编、反编译和分析二进制文件
     3.   **jadx**，[skylot/jadx](https://github.com/skylot/jadx.git)；用于将 Android 应用程序的 DEX 文件反编译成可读的 Java 源代码，有助于理解和修改 Android 应用程序
     4.   **dnspy**，[dnSpy/dnSpy](https://github.com/dnSpy/dnSpy.git)；用于 .NET 程序的反编译器和调试器，允许逆向工程 .NET 应用程序，查看和修改源代码
2.   动态
     1.   **gdb**，[official](https://www.sourceware.org/gdb/)；用于调试程序，支持多种编程语言，可用于跟踪程序的执行过程、检查内存和寄存器状态等，一般不会只使用 gdb，更多要配合插件
     2.   **ollydbg**，[OllyDbg](https://www.ollydbg.de/)；Windows，动态调试器，用于分析和修改程序的运行时行为，主要用于反汇编和跟踪
     3.   **x64dbg/x32dbg**，[x64dbg/x64dbg](https://github.com/x64dbg/x64dbg.git)；开源，支持多种指令集，和 ollydbg 像
     4.   **windbg**，[official](http://www.windbg.org/)；分析 Windows 系统和应用程序
     5.   **cheat engine**，[official](https://www.cheatengine.org/)；改游戏挺常用的
3.   other
     1.   **z3**，[Z3Prover/z3](https://github.com/Z3Prover/z3.git)；用于自动推理和解决数学问题的定理证明器，可用于逆向工程中的符号执行、模型检测等约束求解问题
     2.   **angr**，[angr/angr](https://github.com/angr/angr.git)；开源的二进制分析框架，用于自动化逆向工程任务，包括符号执行、路径探索和程序分析
     3.   **binwalk**，[ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk.git)；固件提取工具
