## python-embed-env-maker

通过 python embedable package 快速创建不同版本的可移植环境（venv），以 python 3.12 为例

1. 在项目下创建文件夹 `venv`
2. 到 [官网](https://www.python.org/downloads/release/python-3120/) 下载对应的 embedable package，解压到 `venv/` 下
3. 补全 python 能力
   1. 获取 pip：`wget https://bootstrap.pypa.io/get-pip.py -O get-pip.py`
   2. 在 `venv/python-3.12.0-embed-amd64/python12._pth` 中去掉 `# import site` 前的注释号
   3. 安装 pip：`venv/python-3.12.0-embed-amd64/python.exe get-pip.py`
   4. `venv/python-3.12.0-embed-amd64/python.exe -m pip install virtualenv`
4. 然后创建虚拟环境：`venv/python-3.12.0-embed-amd64/python.exe -m virtualenv venv`（选定 `venv` 目录作为虚拟环境，且移植后也可以直接使用）
5. `./venv/scripts/activate`

以上步骤完成后，python 项目的目录结构应该如下：

```bash
project
├── venv
│   ├── python-3.12.0-embed-amd64
│   │   ├── python.exe
│   │   ├── pythonw.exe
│   │   ├── python312.zip
│   │   └── ...
│   ├── Lib
│   │   └── site-packages
│   ├── Scripts
│   │   ├── activate
│   │   ├── activate.bat
│   │   ├── activate.ps1
│   │   ├── pip.exe
│   │   ├── python.exe
│   │   └── ...
│   ├── python-3.12.0-embed-amd64.zip
│   ├── .gitignore
│   ├── CACHEDIR.TAG
│   └── pyvenv.cfg
├── src
│   ├── entry.py
│   ├── util.py
│   └── ...
├── README.md
└── main.py
```