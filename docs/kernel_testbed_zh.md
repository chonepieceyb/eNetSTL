## eBPF编译流程和内核测试流程

### 编译eBPF程序

Step1: 

运行 `./scripts/gen_vmlinux_h.sh` 脚本以生成 `vmlinux.h` 头文件，该文件包含内核的BTF信息，供eBPF程序编译时使用。默认情况下，脚本会从编译好的内核映像中提取BTF信息。如果需要从系统BTF中提取，可以使用 `--source system` 选项。

Step2 (option): 

运行 `./scripts/gen_skels.sh` 脚本以生成eBPF程序的骨架代码。该脚本会根据指定的子项目名称和功能列表生成相应的BPF内核代码和用户空间代码。

Step3:

运行 `./scripts/set_white_blacklist.sh -h` 脚本以生成白名单和黑名单文件，这些文件用于制定编译/屏蔽某些实验功能。

Step4: 

运行 `./clean.sh -d && ./build.sh -d -DLOG_LEVEL=4 -DUSE_STATIC=ON -DXDP_IF="eth1" -DXDP_MODE=XDP_FLAGS_SKB_MODE` 
编译所有的用户态和内核态程序，

其中 `-DXDP_IF` 指定XDP程序绑定的网络接口，`-DXDP_MODE` 指定XDP程序的工作模式, -DLOG_LEVEL和-DUSE_STATIC是可选参数，分别用于设置日志级别和是否使用静态链接。具体的编译选项查看 根目录下的 CmakeFiles.txt 文件。

PS: 如果要使用docker进行编译，可以在clean.sh 和 build.sh 脚本中增加 -d -i <image_name> 参数，指定docker镜像名称。具体可以运行 `./clean.sh -h` 和 `./build.sh -h` 查看帮助信息。

### 编译LKM 

到 `src/LKMs/<subproject>/` 目录下，运行 `make` 命令编译LKM模块。

### 启动测试内核

Step1: 生成配置文件

运行 `./scripts/testbed_config.sh` 脚本生成内核测试所需要的配置文件, 查看 `./scripts/testbed_config.sh -h` 获取帮助信息。

Step2:
根据需要修改 `configs/kernel_testbed.conf` 配置文件中的参数。

Step3: 
运行 `./scripts/prepare_kernel.sh` , 会自动拷贝内核，并将编译好的 eBPF加载程序和LKM模块复制到 虚拟机中的  `/home/KERNDBG_VM_USER` 下

注意，如果使用虚拟机进行内核测试，建议编译时候，-DUSE_STATIC=ON 

Step4: 
此时可以运行 gdb 来调试内核，或者使用vscode的gdb插件，一种配置方法为，在根目录下创建
`.vscode/launch.json` 文件，内容（例子，请自行修改相关端口）如下：

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "kernel-debug",
            "type": "cppdbg",
            "request": "launch",
            "miDebuggerServerAddress": "127.0.0.1:1568",
            "program": "${workspaceFolder}/linux/vmlinux",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "logging": {
                "engineLogging": false
            },
            "MIMode": "gdb",
        }
    ]
}
```

Step5: 
如果只是更新eBPF程序而不重启虚拟机，可以运行

`./scripts/copy_files_to_vm.sh` 会自动复制所有编译好的 eBPF加载程序和LKM模块到 虚拟机中的  `/home/KERNDBG_VM_USER` 下

