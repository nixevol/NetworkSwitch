# 网络监控程序 (Network Monitor)

一个基于Go语言开发的Windows网络监控工具，支持双网环境下的自动网络切换和监控控制。

## 功能特性

- 🔄 **自动网络切换**：智能检测内外网连通性，自动切换网络接口
- 🎯 **系统托盘集成**：完全集成到Windows系统托盘，支持右键菜单操作
- ⚙️ **配置文件驱动**：通过config.ini文件灵活配置所有参数
- 🎮 **监控控制**：支持启动/暂停双网检测功能

## 系统要求

- Windows 10/11 (x64)
- 管理员权限（用于网络接口控制）
- Go 1.21+ （仅编译时需要）

## 快速开始

### 下载使用

1. 从 [Releases](../../releases) 页面下载最新版本的 `network_monitor.exe`
2. 将程序放置到任意目录
3. 确保同目录下有 `config.ini` 和 `icon.ico` 文件
4. 右键以管理员身份运行程序

### 编译安装

#### 环境准备

```bash
# 安装Go语言环境 (https://golang.org/dl/)
# 确保Go版本 >= 1.21
go version
```

#### 克隆项目

```bash
git clone https://github.com/nixevol/network-monitor.git
cd network-monitor
```

#### 安装依赖

```bash
go mod tidy
```

#### 编译程序

**标准编译（带控制台窗口）：**
```bash
go build -o network_monitor.exe
```

**无窗口编译（推荐）：**
```bash
go build -ldflags="-H windowsgui" -o network_monitor.exe
```

## 配置说明

### config.ini 配置文件

```ini
[network]
; 内网检测IP地址
internal_ip=188.5.106.1
; 外网检测IP地址
external_ip=192.168.33.1
; 内网连接名称
internal_conn=OSS
; 外网连接名称
external_conn=NET

[monitor]
; 定时检测间隔（秒）
check_interval=10

[ui]
; 托盘图标路径（相对路径基于程序所在目录）
icon_path=icon.ico
; 托盘标题
title=网络监控
; 托盘提示信息
tooltip=网络接口监控程序
```

### 配置参数详解

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `internal_ip` | 内网检测目标IP | 188.5.106.1 |
| `external_ip` | 外网检测目标IP | 192.168.33.1 |
| `internal_conn` | 内网网络连接名称 | OSS |
| `external_conn` | 外网网络连接名称 | NET |
| `check_interval` | 检测间隔（秒） | 10 |
| `icon_path` | 图标文件路径 | icon.ico |
| `title` | 系统托盘标题 | 网络监控 |
| `tooltip` | 系统托盘提示 | 网络接口监控程序 |

## 使用方法

### 启动程序

1. **右键以管理员身份运行** `network_monitor.exe`
2. 程序将在系统托盘显示图标
3. 程序开始自动监控网络状态

### 系统托盘操作

右键点击系统托盘图标，可以看到以下菜单：

- **网络切换**：手动切换网络接口
- **暂停监控** / **启动监控**：控制自动监控开关
- **退出**：退出程序

### 工作原理

1. **连通性检测**：程序定时检测内网和外网的连通性
2. **智能切换**：根据检测结果自动启用/禁用相应的网络接口
3. **优先级管理**：在双网可用时，优先保留包含"Net"的网络接口
4. **手动控制**：支持通过右键菜单手动切换网络

## 开发说明

### 项目结构

```
network-monitor/
├── network_monitor.go    # 主程序源码
├── config.ini           # 配置文件
├── icon.ico            # 系统托盘图标
├── go.mod              # Go模块文件
├── go.sum              # 依赖校验文件
├── README.md           # 说明文档
└── .gitignore          # Git忽略文件
```

### 主要依赖

- [github.com/getlantern/systray](https://github.com/getlantern/systray) - 系统托盘功能
- Windows API - 网络接口管理

### 编译选项

- `-ldflags="-H windowsgui"`：编译为无控制台窗口的GUI程序
- `-o network_monitor.exe`：指定输出文件名

## 故障排除

### 常见问题

**Q: 程序无法启动或没有托盘图标？**
A: 确保以管理员权限运行程序，并检查config.ini文件是否存在。

**Q: 网络切换不生效？**
A: 检查config.ini中的网络连接名称是否与系统中的实际名称一致。

**Q: 图标不显示？**
A: 确保icon.ico文件存在，或检查config.ini中icon_path配置是否正确。

**Q: 监控功能异常？**
A: 检查内网和外网IP地址配置是否正确，确保目标IP可达。

### 日志调试

如果需要查看详细日志，可以使用标准编译版本：
```bash
go build -o network_monitor.exe
./network_monitor.exe
```

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 发布版本

### 自动发布（推荐）

1. **创建Git标签**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions自动构建**
   - 推送标签后，GitHub Actions会自动构建多平台版本
   - 自动创建GitHub Release并上传文件
   - 生成完整的发布说明

### 手动发布

1. **使用构建脚本**
   ```powershell
   .\build_release.ps1 -Version "v1.0.0" -OpenFolder
   ```

2. **手动上传到GitHub Releases**
   - 访问仓库的Releases页面
   - 创建新发布并上传构建的文件

详细发布流程请参考 [RELEASE.md](RELEASE.md) 文档。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v1.0.0
- 初始版本发布
- 支持双网自动切换
- 系统托盘集成
- 配置文件支持
- 监控控制功能
