install-is-canceled = 安装进程已被取消。
another-install-is-running = 另一安装程序实例正在运行。
install-from-config = 正使用无人值守配置 { $path } 安装 AOSC OS ...
formatting-partition = 正在格式化分区
downloading-system-release = 正在下载系统包
unpacking-system-release = 正在解包系统
generating-fstab = 正在生成启动磁盘挂载配置文件 (fstab)
generating-initramfs = 正在生成初始内存盘 (initramfs)
installing-bootloader = 正在安装及配置 GRUB 引导器
generating-ssh-key = 正在生成 SSH 密钥
finalizing-installation = 正在执行最终配置
finished = 安装已成功完成。请使用 `reboot -f' 命令重启电脑，并立刻拔除或弹出安装介质（如 U 盘或 DVD 光盘）。随后，您的设备将重启到 AOSC OS。
direct-efi-error = 安装程序无法确定是否运行在 EFI 设备上。
efi-field-not-set = 无人值守配置未定义 `efi_disk' 条目。
invaild-fullname = 用户全名无效：{ $e }
invaild-username = UNIX 用户名无效：{ $e }
invaild-hostname = 主机名无效：{ $e }
invaild-locale = 无效系统语言：{ $s }
invaild-timezone = 无效时区：{ $s }
invaild-target-partition = 找不到指定的目标系统分区或目标分区存储空间不足。
invaild-efi-partition = 找不到指定的 EFI 系统分区 (ESP) 。
offline-mode = 探测到离线安装数据，是否使用离线模式安装 AOSC OS？
variant = 系统版本
list-of-device = 可用存储设备列表：
no-device-to-install = 没有可用于安装 AOSC OS 的存储设备。
no-partition-to-install = 指定的存储设备中没有可用于安装 AOSC OS 的分区。
select-device = 存储设备
auto-partiton = 是否需要安装程序自动分区？(y/n)
direct-lvm-error = 无法确定该存储设备是否为 LVM 设备。
unsupport-lvm-device = 安装程序不支持在 LVM 设备上安装 AOSC OS。
select-system-partition = 系统分区
no-efi-partition = 指定的存储设备上没有可用的 EFI 系统分区 (ESP) 。
select-efi-partition = EFI 系统分区 (ESP)
fullname = 用户全名（可选）
username = UNIX 用户名
hostname = 主机名
locale = 系统语言
timezone = 时区
password = 密码
rtc-as-localtime = 是否使用硬件时钟 (RTC) 作为系统时间？
swap-size = 虚拟内存文件 (swapfile) 大小 (GiB)
hostname-illegal = 指定的主机名中包含无效字符：{ $c }
hostname-illegal-startswith = 指定的主机名以无效字符字符开头：{ $c }
username-illegal = 指定的 UNIX 用户名中包含无效字符：{ $c }
username-illegal-starts-with-number = 指定的 UNIX 用户名中开头不能是数字。
fullname-illegal = 指定的用户全名中包含无效字符：':'
squashfs-empty = 系统发行元数据文件中未包含 `squashfs'，该元数据文件可能已损坏。
confirm-password = 确认密码
confirm = 您确定要安装 AOSC OS 吗？若继续，相关分区及存储设备上的数据**将被清空**！
confirm-autopart = 您确定要自动分区吗？若继续，指定存储设备上的数据**将被清空**！
confirm-prompt = 是否继续 (y/n)
downloading-recipe = 正在下载系统发行元数据 ...
auto-partition-working = 正在进行自动分区，请稍候 ...
confirm-password-not-matching = 您指定的密码不匹配，请重试。
password-required = 需设置密码。
hostname-required = 需设置有效主机名。
username-required = 需设置有效 UNIX 用户名。
yn-confirm-required = 请确认操作：按 'Y' 确认，按 'N' 中止操作。
installation-aborted = 已中止安装。
hostname-illegal-ends-with = 指定的主机名以无效字符结尾：{ $c }
hostname-illegal-too-loong = 指定的主机名过长。
hostname-illegal-starts-with = 指定的主机名包含无效字符：{ $c }
hostname-illegal-double-dot = 指定的主机名包含不允许存在的字符组合：两个或更多连续的点 (`..')。
partition-unformatted = 分区 { $path } 未格式化，安装程序将把该分区格式化为 ext4 文件系统。
