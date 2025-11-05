//go:build windows
// +build windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"github.com/getlantern/systray"
)

// Windows API 常量
const (
	IF_OPER_STATUS_UP               = 1
	IF_OPER_STATUS_DOWN             = 2
	IF_OPER_STATUS_TESTING          = 3
	IF_OPER_STATUS_UNKNOWN          = 4
	IF_OPER_STATUS_DORMANT          = 5
	IF_OPER_STATUS_NOT_PRESENT      = 6
	IF_OPER_STATUS_LOWER_LAYER_DOWN = 7
	NET_IF_ADMIN_STATUS_UP          = 1
	NET_IF_ADMIN_STATUS_DOWN        = 2
	NET_IF_ADMIN_STATUS_TESTING     = 3
)

// Windows API 结构体
type MIB_IF_ROW2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               [16]byte
	Alias                       [257]uint16
	Description                 [257]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 [16]byte
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

type MIB_IF_TABLE2 struct {
	NumEntries uint32
	Table      [1]MIB_IF_ROW2
}

// Windows API 函数
var (
	iphlpapi         = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIfTable2  = iphlpapi.NewProc("GetIfTable2")
	procFreeMibTable = iphlpapi.NewProc("FreeMibTable")
)

// Config 保存应用程序配置
type Config struct {
	InternalIP    string // 内网检测IP地址
	ExternalIP    string // 外网检测IP地址
	InternalConn  string // 内网连接名称
	ExternalConn  string // 外网连接名称
	CheckInterval int    // 定时检测间隔（秒）
	IconPath      string // 图标路径
	Title         string // 托盘标题
	Tooltip       string // 托盘提示信息
}

var (
	config            *Config
	monitoringEnabled bool         = true // 双网检测开关状态
	monitorTicker     *time.Ticker        // 定时器
	startupEnabled    bool                // 开机启动状态
)

// isStartupEnabled 检查是否已设置开机启动
func isStartupEnabled() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	// 获取程序名称（不含路径）
	appName := filepath.Base(exePath)
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))

	value, _, err := key.GetStringValue(appName)
	if err != nil {
		return false
	}

	// 检查值是否匹配当前可执行文件路径
	return value == exePath
}

// setStartup 设置开机启动
func setStartup(enable bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("无法打开注册表项: %v", err)
	}
	defer key.Close()

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取可执行文件路径: %v", err)
	}

	// 获取程序名称（不含路径）
	appName := filepath.Base(exePath)
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))

	if enable {
		// 设置开机启动
		err = key.SetStringValue(appName, exePath)
		if err != nil {
			return fmt.Errorf("设置开机启动失败: %v", err)
		}
		log.Printf("已设置开机启动: %s", appName)
	} else {
		// 取消开机启动
		err = key.DeleteValue(appName)
		if err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("取消开机启动失败: %v", err)
		}
		log.Printf("已取消开机启动: %s", appName)
	}

	return nil
}

// toggleStartup 切换开机启动状态
func toggleStartup(menuItem *systray.MenuItem) {
	newState := !startupEnabled
	if err := setStartup(newState); err != nil {
		log.Printf("设置开机启动失败: %v", err)
		return
	}

	startupEnabled = newState
	updateStartupMenuItem(menuItem)
}

// updateStartupMenuItem 更新开机启动菜单项标题和提示
func updateStartupMenuItem(menuItem *systray.MenuItem) {
	if startupEnabled {
		menuItem.SetTitle("取消开机启动")
		menuItem.SetTooltip("取消开机启动")
	} else {
		menuItem.SetTitle("设置开机启动")
		menuItem.SetTooltip("设置开机启动")
	}
}

// updateNetworkSwitchMenuItem 更新网络切换菜单项标题
func updateNetworkSwitchMenuItem(menuItem *systray.MenuItem) {
	nextTarget := getNextNetworkTarget()
	if nextTarget == "" {
		menuItem.SetTitle("网络切换")
		menuItem.SetTooltip("切换网络接口")
		return
	}

	menuItem.SetTitle(fmt.Sprintf("切换网络至[%s]", nextTarget))
	menuItem.SetTooltip(fmt.Sprintf("切换到 %s 网络接口", nextTarget))
}

// loadConfig 从config.ini文件加载配置
func loadConfig() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "config.ini")

	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	config = &Config{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "internal_ip":
				config.InternalIP = value
			case "external_ip":
				config.ExternalIP = value
			case "internal_conn":
				config.InternalConn = value
			case "external_conn":
				config.ExternalConn = value
			case "check_interval":
				if interval, err := strconv.Atoi(value); err == nil {
					config.CheckInterval = interval
				} else {
					config.CheckInterval = 60 // 默认60秒
				}
			case "icon_path":
				config.IconPath = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	// 设置默认检测间隔
	if config.CheckInterval <= 0 {
		config.CheckInterval = 60 // 默认60秒
	}

	// 如果图标路径是相对路径，则相对于exe目录
	if config.IconPath != "" && !filepath.IsAbs(config.IconPath) {
		config.IconPath = filepath.Join(exeDir, config.IconPath)
	}

	return nil
}

// NetworkInterface 表示网络接口
type NetworkInterface struct {
	Index       uint32
	Name        string
	Description string
	IsEnabled   bool
	OperStatus  uint32
	Luid        uint64
}

// GetNetworkInterfaces 获取所有网络接口
func GetNetworkInterfaces() ([]NetworkInterface, error) {
	var table *MIB_IF_TABLE2
	ret, _, _ := procGetIfTable2.Call(uintptr(unsafe.Pointer(&table)))
	if ret != 0 {
		return nil, fmt.Errorf("GetIfTable2 failed with error: %d", ret)
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	var interfaces []NetworkInterface
	for i := uint32(0); i < table.NumEntries; i++ {
		row := (*MIB_IF_ROW2)(unsafe.Pointer(uintptr(unsafe.Pointer(&table.Table[0])) + uintptr(i)*unsafe.Sizeof(table.Table[0])))

		// 将UTF-16转换为字符串
		alias := syscall.UTF16ToString(row.Alias[:])
		description := syscall.UTF16ToString(row.Description[:])

		interfaces = append(interfaces, NetworkInterface{
			Index:       row.InterfaceIndex,
			Name:        alias,
			Description: description,
			IsEnabled:   row.AdminStatus == NET_IF_ADMIN_STATUS_UP,
			OperStatus:  row.OperStatus,
			Luid:        row.InterfaceLuid,
		})
	}

	return interfaces, nil
}

// EnableInterface 使用netsh启用网络接口
func EnableInterface(name string) error {
	cmd := fmt.Sprintf(`netsh interface set interface "%s" admin=enable`, name)
	return runNetshCommand(cmd)
}

// DisableInterface 使用netsh禁用网络接口
func DisableInterface(name string) error {
	cmd := fmt.Sprintf(`netsh interface set interface "%s" admin=disable`, name)
	return runNetshCommand(cmd)
}

// runNetshCommand 执行netsh命令
func runNetshCommand(cmd string) error {
	// 跳过虚拟和回环接口
	if strings.Contains(cmd, "Loopback") || strings.Contains(cmd, "WFP") || strings.Contains(cmd, "QoS") {
		return nil
	}

	// 使用WinExec执行命令以提高可靠性
	execCmd := fmt.Sprintf(`cmd /c "%s"`, cmd)
	exec := syscall.NewLazyDLL("kernel32.dll").NewProc("WinExec")
	ret, _, _ := exec.Call(uintptr(unsafe.Pointer(syscall.StringBytePtr(execCmd))), 0)
	if ret == 0 {
		return fmt.Errorf("执行命令失败: %s", cmd)
	}
	return nil
}

// CheckConnectivity 检查网络连通性
func CheckConnectivity() (bool, bool) {
	if config == nil {
		log.Printf("Config not loaded, using default values")
		return false, false
	}

	// 首先检查网络接口是否启用
	internalInterfaceEnabled := isInterfaceEnabled(config.InternalConn)
	externalInterfaceEnabled := isInterfaceEnabled(config.ExternalConn)

	// 只有接口启用时才测试连通性
	var internalOK, externalOK bool
	if internalInterfaceEnabled {
		internalOK = testConnection(config.InternalIP+":80", 3*time.Second)
	}
	if externalInterfaceEnabled {
		externalOK = testConnection(config.ExternalIP+":80", 3*time.Second)
	}

	return internalOK, externalOK
}

// testConnection 测试TCP连接
func testConnection(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isInterfaceEnabled 检查指定名称的网络接口是否启用
func isInterfaceEnabled(interfaceName string) bool {
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return false
	}

	for _, iface := range interfaces {
		if iface.Name == interfaceName {
			return iface.IsEnabled && iface.OperStatus == IF_OPER_STATUS_UP
		}
	}
	return false
}

// getCurrentActiveNetwork 获取当前活动的网络接口名称
func getCurrentActiveNetwork() string {
	if config == nil {
		return ""
	}

	// 检查内网是否启用
	if isInterfaceEnabled(config.InternalConn) {
		return config.InternalConn
	}

	// 检查外网是否启用
	if isInterfaceEnabled(config.ExternalConn) {
		return config.ExternalConn
	}

	return ""
}

// getInterfaceIP 获取指定网络接口的IP地址
func getInterfaceIP(interfaceName string) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		if iface.Name == interfaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return ""
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						return ipNet.IP.String()
					}
				}
			}
		}
	}
	return ""
}

// updateTooltip 更新托盘提示信息
func updateTooltip() {
	currentNetwork := getCurrentActiveNetwork()
	if currentNetwork == "" {
		systray.SetTooltip("切换网络\n当前: 无连接")
		return
	}

	ip := getInterfaceIP(currentNetwork)
	if ip == "" {
		systray.SetTooltip(fmt.Sprintf("切换网络\n当前: %s\nIP: 获取中...", currentNetwork))
	} else {
		systray.SetTooltip(fmt.Sprintf("切换网络\n当前: %s\nIP: %s", currentNetwork, ip))
	}
}

// getNextNetworkTarget 获取下一个要切换的网络接口名称
func getNextNetworkTarget() string {
	current := getCurrentActiveNetwork()

	if current == "" {
		// 如果没有活动的网络，默认返回外网
		if config != nil {
			return config.ExternalConn
		}
		return ""
	}

	if config == nil {
		return ""
	}

	// 如果当前是内网，返回外网
	if current == config.InternalConn {
		return config.ExternalConn
	}

	// 如果当前是外网，返回内网
	if current == config.ExternalConn {
		return config.InternalConn
	}

	// 默认返回外网
	return config.ExternalConn
}

// NetworkMonitor 管理网络接口
type NetworkMonitor struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewNetworkMonitor 创建新的网络监控器
func NewNetworkMonitor() *NetworkMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkMonitor{
		ctx:    ctx,
		cancel: cancel,
	}
}

// StartMonitoring 启动网络监控循环
func (nm *NetworkMonitor) StartMonitoring() {
	interval := time.Duration(config.CheckInterval) * time.Second
	monitorTicker = time.NewTicker(interval)

	// 初始检查
	nm.checkAndManageInterfaces()

	for {
		select {
		case <-nm.ctx.Done():
			return
		case <-monitorTicker.C:
			if monitoringEnabled {
				nm.checkAndManageInterfaces()
			}
		}
	}
}

// checkAndManageInterfaces 检查连通性并管理接口
func (nm *NetworkMonitor) checkAndManageInterfaces() {
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return
	}

	internalOK, externalOK := CheckConnectivity()

	if internalOK && externalOK {
		// 内网和外网都可访问，只保留Net接口
		var netInterface *NetworkInterface
		var otherInterfaces []NetworkInterface

		for _, iface := range interfaces {
			if iface.IsEnabled && iface.OperStatus == IF_OPER_STATUS_UP {
				if strings.Contains(strings.ToLower(iface.Name), "net") {
					netInterface = &iface
				} else {
					otherInterfaces = append(otherInterfaces, iface)
				}
			}
		}

		if netInterface != nil {
			// 禁用其他接口
			for _, iface := range otherInterfaces {
				log.Printf("禁用接口: %s", iface.Name)
				if err := DisableInterface(iface.Name); err != nil {
					log.Printf("禁用接口失败 %s: %v", iface.Name, err)
				}
			}
		} else {
			// 未找到Net接口，保留第一个启用的接口
			if len(otherInterfaces) > 1 {
				for i := 1; i < len(otherInterfaces); i++ {
					log.Printf("禁用接口: %s", otherInterfaces[i].Name)
					if err := DisableInterface(otherInterfaces[i].Name); err != nil {
						log.Printf("禁用接口失败 %s: %v", otherInterfaces[i].Name, err)
					}
				}
			}
		}
	}
}

// NetworkSwitch 切换到下一个可用的网络接口
func (nm *NetworkMonitor) NetworkSwitch() {
	if config == nil {
		log.Printf("配置未加载，无法切换网络")
		return
	}

	// 检查当前连通性以确定要切换到哪个网络
	internalOK, externalOK := CheckConnectivity()

	var targetConn, disableConn string
	if internalOK {
		// 当前在内网，切换到外网
		targetConn = config.ExternalConn
		disableConn = config.InternalConn
		log.Printf("检测到内网，切换到外网")
	} else if externalOK {
		// 当前在外网，切换到内网
		targetConn = config.InternalConn
		disableConn = config.ExternalConn
		log.Printf("检测到外网，切换到内网")
	} else {
		// 无连接，默认尝试启用外网
		targetConn = config.ExternalConn
		disableConn = config.InternalConn
		log.Printf("未检测到网络连接，尝试外网")
	}

	// 首先禁用当前连接
	log.Printf("禁用接口: %s", disableConn)
	if err := DisableInterface(disableConn); err != nil {
		log.Printf("禁用接口失败 %s: %v", disableConn, err)
	}

	// 减少等待时间以提高切换速度
	time.Sleep(1 * time.Second)

	// 然后启用目标连接
	log.Printf("启用接口: %s", targetConn)
	if err := EnableInterface(targetConn); err != nil {
		log.Printf("启用接口失败 %s: %v", targetConn, err)
	} else {
		log.Printf("成功切换到接口: %s", targetConn)
	}
}

// Stop 停止监控
func (nm *NetworkMonitor) Stop() {
	nm.cancel()
}

var monitor *NetworkMonitor

func onReady() {
	// 检查当前开机启动状态
	startupEnabled = isStartupEnabled()

	// 设置系统托盘图标、标题和提示
	systray.SetIcon(getIcon())
	// 设置托盘标题和提示信息
	if config != nil && config.Title != "" {
		systray.SetTitle(config.Title)
	} else {
		systray.SetTitle("网络监控")
	}

	if config != nil && config.Tooltip != "" {
		systray.SetTooltip(config.Tooltip)
	} else {
		systray.SetTooltip("网络接口监控程序")
	}

	// 创建菜单项
	mNetworkSwitch := systray.AddMenuItem("网络切换", "切换网络接口")
	mToggleMonitor := systray.AddMenuItem("暂停双网检测", "启动/暂停双网检测")
	mStartupToggle := systray.AddMenuItem("设置开机启动", "设置/取消开机启动")
	mQuit := systray.AddMenuItem("退出", "退出程序")

	// 更新开机启动菜单项状态
	updateStartupMenuItem(mStartupToggle)

	// 初始更新网络切换菜单项标题
	updateNetworkSwitchMenuItem(mNetworkSwitch)

	// 启动网络监控
	monitor = NewNetworkMonitor()
	go monitor.StartMonitoring()

	// 启动定时更新网络切换菜单项标题和托盘提示
	go func() {
		ticker := time.NewTicker(5 * time.Second) // 每5秒更新一次
		defer ticker.Stop()

		// 初始更新
		updateTooltip()

		for {
			select {
			case <-ticker.C:
				updateNetworkSwitchMenuItem(mNetworkSwitch)
				updateTooltip()
			}
		}
	}()

	// 处理菜单点击事件
	go func() {
		for {
			select {
			case <-mNetworkSwitch.ClickedCh:
				go func() {
					monitor.NetworkSwitch()
					// 切换后更新菜单项标题和托盘提示
					time.Sleep(2 * time.Second)
					updateNetworkSwitchMenuItem(mNetworkSwitch)
					updateTooltip()
				}()
			case <-mToggleMonitor.ClickedCh:
				go toggleMonitoring(mToggleMonitor)
			case <-mStartupToggle.ClickedCh:
				go toggleStartup(mStartupToggle)
			case <-mQuit.ClickedCh:
				if monitorTicker != nil {
					monitorTicker.Stop()
				}
				systray.Quit()
				return
			}
		}
	}()
}

func onExit() {
	if monitor != nil {
		monitor.Stop()
	}
}

// toggleMonitoring 切换监控状态
func toggleMonitoring(menuItem *systray.MenuItem) {
	monitoringEnabled = !monitoringEnabled
	if monitoringEnabled {
		menuItem.SetTitle("暂停双网检测")
		menuItem.SetTooltip("暂停双网检测")
		log.Println("双网检测已启动")
	} else {
		menuItem.SetTitle("启动双网检测")
		menuItem.SetTooltip("启动双网检测")
		log.Println("双网检测已暂停")
	}
}

// getIcon 返回系统托盘图标数据
func getIcon() []byte {
	if config != nil && config.IconPath != "" {
		// 尝试从文件加载图标
		if iconData, err := os.ReadFile(config.IconPath); err == nil {
			return iconData
		} else {
			log.Printf("加载图标失败 %s: %v", config.IconPath, err)
		}
	}

	// 回退到默认图标
	return []byte{
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x68, 0x04,
		0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// 像素数据 - 简单的蓝色方块图案
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF,
		0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF,
		0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func main() {
	// 设置日志输出到stderr以在GUI模式下抑制输出
	log.SetOutput(os.Stderr)

	// 加载配置
	if err := loadConfig(); err != nil {
		log.Printf("警告: 加载配置失败: %v", err)
		log.Printf("使用默认配置")
	}

	// 运行系统托盘应用程序
	systray.Run(onReady, onExit)
}
