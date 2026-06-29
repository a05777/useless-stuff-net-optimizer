package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// 检查是否拥有管理员权限
func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// 极其严格的 PowerShell 执行器（修复“假成功”漏洞）
func runPowerShell(script string) error {
	// 1. 强制注入 Stop 偏好，将所有隐藏的非终止错误（如拦截、参数错误）升级为终止错误
	// 2. 使用 -NoProfile -NonInteractive 避免加载用户自定义环境，提高执行速度和纯净度
	strictScript := fmt.Sprintf("$ErrorActionPreference = 'Stop'; %s", script)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", strictScript)
	
	// 捕获标准输出和标准错误
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// 情况 A：进程级别返回了非 0 状态码
	if err != nil {
		return fmt.Errorf("执行终止（代码异常）. 详情: %s", strings.TrimSpace(outStr))
	}

	// 情况 B：进程装死（返回0），但输出流中包含明确的 localized 错误特征
	lowerOut := strings.ToLower(outStr)
	errorKeywords := []string{"error", "错误", "拒绝访问", "permissiondenied", "failed", "无法"}
	for _, keyword := range errorKeywords {
		if strings.Contains(lowerOut, keyword) {
			return fmt.Errorf("脚本执行触发潜在拦截/错误. 详情: %s", strings.TrimSpace(outStr))
		}
	}

	return nil
}

// 交互式读取输入
func readInput(prompt string, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// 询问 Y/N
func askYesNo(prompt string) bool {
	res := readInput(prompt+" (y/n)", "n")
	return strings.ToLower(res) == "y"
}

// 封装的 MTU 核心探测函数
func probeMTU(domain string) int {
	fmt.Printf("正在对 [%s] 进行不分包 MTU 轮询探测...\n", domain)
	mtuTargets := []int{672, 1280, 1492, 1500}
	optimalMTU := 0

	for _, mtu := range mtuTargets {
		payloadSize := mtu - 28
		if payloadSize <= 0 {
			continue
		}

		cmd := exec.Command("ping", domain, "-f", "-l", fmt.Sprintf("%d", payloadSize), "-n", "1", "-w", "1000")
		err := cmd.Run()
		if err == nil {
			fmt.Printf("  -> 测试 MTU %d (负载 %d 字节): [成功] 数据安全送达。\n", mtu, payloadSize)
			if mtu > optimalMTU {
				optimalMTU = mtu
			}
		} else {
			fmt.Printf("  -> 测试 MTU %d (负载 %d 字节): [失败] 数据包分片或超时。\n", mtu, payloadSize)
		}
	}
	return optimalMTU
}

func main() {
	// 1. 打印许可证与免责声明
	fmt.Println("软件许可及免责声明 / Software License & Disclaimer")
	fmt.Println("该软件以GPLv3许可证开源\n")
	fmt.Println("本程序按“原样”（AS IS）提供，不附带任何形式的明示或暗示保证。作者不保证程序符合特定用途，亦不保证运行过程中不出现错误。\n")
	fmt.Println("在任何情况下，作者不对因使用本程序产生的任何损害（包括但不限于数据丢失、系统崩溃、法律诉讼等）承担任何责任。作者的全部赔偿责任上限在任何情况下均不超过用户实际支付的授权费用（如有）。\n")
	fmt.Println("用户一旦运行、调试或以任何方式使用本程序，即视为完全理解并接受上述条款。作者保留对本协议的最终解释权，并有权随时更新授权条款。\n")
	fmt.Println("By a05777")

	if !askYesNo("您是否同意上述许可证内容并继续运行？（y/n,Default n）") {
		fmt.Println("用户拒绝许可证，程序已直接退出。")
		return
	}

	// 2. 检查管理员权限
	if !isAdmin() {
		fmt.Println("\n[错误] 检测到权限不足！请右键点击本程序选择 '以管理员身份运行'。")
		readInput("按回车键退出...", "")
		return
	}

	for {
		fmt.Println("\n=== 主菜单 ===")
		fmt.Println("1. 开始互动式网络优化（每项均有合规告知）")
		fmt.Println("2. 一键恢复默认网络配置（安全重置模式）")
		fmt.Println("3. 退出程序")
		choice := readInput("请选择操作 (1-3)", "3")

		switch choice {
		case "1":
			startOptimization()
		case "2":
			startRollback()
		case "3":
			fmt.Println("程序已安全退出。")
			return
		default:
			fmt.Println("无效选择，请重新输入。")
		}
	}
}

func startOptimization() {
	fmt.Println("\n--- 开始互动式网络优化配置 ---")

	domain := readInput("请输入您的目标游戏服务器域名", "mc.hypixel.net")
	fmt.Println()
	
	optimalMTU := probeMTU(domain)

	// 智能回落
	if optimalMTU == 0 {
		fmt.Println("\n[提示] 目标服务器对不分包探测无响应（对方防火墙拦截）。")
		fmt.Println("👉 正在启动回落机制：尝试探测国内核心节点 (www.baidu.com) 已获取本地基础 MTU...")
		optimalMTU = probeMTU("www.baidu.com")
		
		if optimalMTU == 0 {
			fmt.Println("\n[警告] 回落节点探测亦失败，网络环境受限。系统退守标准默认值。")
			optimalMTU = 1492
		}
	}

	// 1. MTU 更改
	fmt.Println("\n--------------------------------------------------------------")
	fmt.Printf("【检测结果】最适合您当前网络且不分包的稳定 MTU 值为: %d\n", optimalMTU)
	fmt.Println("【优化目的】防止网络数据包在传输途中被光猫或运营商网关强行肢解（分片）。不分片能显著降低网络重传率，让游戏发包和网页加载更流畅。")
	fmt.Println("【潜在风险】若极个别用户使用了VPN、特殊代理或老旧PPPoE宽带，过大的MTU可能导致某些特定网页或软件打不开。若遇到此情况，可随时运行本工具的一键恢复模式。")
	fmt.Println("--------------------------------------------------------------")
	if askYesNo(fmt.Sprintf("是否将系统所有物理网卡的 MTU 修改为稳定值 %d？", optimalMTU)) {
		script := fmt.Sprintf(`Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.CompartmentId -eq 1} | Set-NetIPInterface -NlMtuBytes %d`, optimalMTU)
		if err := runPowerShell(script); err == nil {
			fmt.Printf("[成功] MTU 已成功修改为 %d。\n", optimalMTU)
		} else {
			fmt.Printf("[失败] 更改 MTU 被拦截或失败: %v\n", err)
		}
	}

	// 2. 关闭 Nagle 算法
	fmt.Println("\n--------------------------------------------------------------")
	fmt.Println("【项目名称】禁用 Nagle 算法 (注册表底层调优)")
	fmt.Println("【优化目的】Windows 默认会把很多游戏发送的微小数据包（比如你走位、开枪的指令）积攒在一起凑成大包再发，用来省带宽。关闭它能强迫网卡“有包即发”，彻底消除由于攒包带来的物理延迟。")
	fmt.Println("【潜在风险】网络总吞吐中的数据包小头开销会轻微变多。在带宽极其恶劣（如1Mbps以下）或路由器极端老旧的极个别环境下可能会增加丢包率，但对现代百兆/千兆宽带完全无害。")
	fmt.Println("--------------------------------------------------------------")
	if askYesNo("是否关闭 Nagle 算法（强迫网卡拒绝攒包，立刻发送微小指令）？") {
		fmt.Println("正在扫描活动网卡并写入注册表...")
		script := `
		$path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
		Get-ChildItem $path | ForEach-Object {
			$sub = $_.PSChildName
			if ((Get-ItemProperty "$path\$sub" -Name "IPAddress" -ErrorAction SilentlyContinue) -or (Get-ItemProperty "$path\$sub" -Name "DhcpIPAddress" -ErrorAction SilentlyContinue)) {
				Set-ItemProperty "$path\$sub" -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
				Set-ItemProperty "$path\$sub" -Name "TCPNoDelay" -Value 1 -Type DWord -Force
			}
		}`
		if err := runPowerShell(script); err == nil {
			fmt.Println("[成功] Nagle 算法已关闭（注册表优化成功注入）。")
		} else {
			fmt.Printf("[失败] 注册表修改失败: %v\n", err)
		}
	}

// 3. QoS 优先级策略
    fmt.Println("\n--------------------------------------------------------------")
    fmt.Printf("【项目名称】更改 [%s] 的 QoS 优先级\n", domain)
    fmt.Println("【优化目的】程序会实时查询该域名背后的所有真实服务器 IP，并在 Windows 内核中为它们创建专属 QoS 策略，打上最高优先级标记 (DSCP 46)。这能确保当你在下载或后台有其他流量时，发往该游戏服务器的数据包依然能在系统和高级路由器中无条件插队、优先发送。")
    fmt.Println("【潜在风险】对系统本身无任何坏处。但请注意：部分 Windows 家庭版由于阉割了组策略组件，此项指令可能会报错或无法生效；此外，普通家用宽带运营商在出境国际网关处可能会无视或剥离此优先级标记，因此外服效果因人而异，并且游戏服务器存在IP变动的问题，如IP已变更，请重新运行本工具。")
    fmt.Println("--------------------------------------------------------------")
    if askYesNo(fmt.Sprintf("是否将发往域名 '%s' 的数据包在系统中赋予最高 QoS 优先级？", domain)) {
        fmt.Printf("正在解析 %s 的最新 IP 映射...\n", domain)
        ips, err := net.LookupIP(domain)
        if err != nil {
            fmt.Printf("[失败] 无法解析该域名，QoS 策略未创建: %v\n", err)
        } else {
            var ipStrings []string
            for _, ip := range ips {
                if ip.To4() != nil {
                    ipStrings = append(ipStrings, fmt.Sprintf("'%s'", ip.String()))
                }
            }
            if len(ipStrings) == 0 {
                fmt.Println("[失败] 未能获取到该域名的有效 IPv4 地址。")
            } else {
                fmt.Println("正在清理旧的 QoS 冲突策略...")
                // 使用带有通配符的批量清理，防止重名和多余策略残留
                _ = runPowerShell(`Get-NetQosPolicy -Name "GoNetOpt_QoS_*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false`)

                fmt.Println("正在为每个解析出的 IP 独立构建高级 QoS 策略...")
                var psCommands []string
                for i, ipStr := range ipStrings {
                    // 为每一个 IP 独立生成单条合法命令，解决 -IPDstPrefixMatchCondition 不吃数组的问题
                    cmdStr := fmt.Sprintf(`New-NetQosPolicy -Name "GoNetOpt_QoS_%d" -DSCPAction 46 -IPDstPrefixMatchCondition %s -Confirm:$false`, i, ipStr)
                    psCommands = append(psCommands, cmdStr)
                }

                // 用分号将多条 PowerShell 命令合并
                script := strings.Join(psCommands, "; ")
                
                if err := runPowerShell(script); err == nil {
                    fmt.Printf("[成功] 已成功为该域名创建最高优先级 QoS 策略 (%d 个 IP 已独立加入 VIP 链路)。\n", len(ipStrings))
                } else {
                    fmt.Printf("[失败] 创建失败（可能系统版本不支持高级QoS组策略，或权限被拦截）: %v\n", err)
                }
            }
        }
    }

	// 4. 网卡高级属性
// 4. 网卡高级属性
    fmt.Println("\n--------------------------------------------------------------")
    fmt.Println("【项目名称】微调网卡高级硬件属性（关闭中断节流、节能、LSO）")
    fmt.Println("【优化目的】\n 1. 关闭[中断节流]: 让网卡一收到网络包就立刻叫醒 CPU 处理，不再为了省CPU而故意延迟合并处理。\n 2. 关闭[节能以太网]: 阻止网卡在没有大量数据时偷偷进入低功耗休眠，引发瞬间网络唤醒卡顿。\n 3. 关闭[大发包载卸(LSO)]: 将计算切包的工作交还给更强劲的 CPU 处理，避免部分网卡固件较烂导致硬件层面的卡顿丢包。")
    fmt.Println("【潜在风险】\n 1. 执行瞬间网卡会重置，导致网络短暂断开 1-2 秒，请勿在关键下载或对局中操作！\n 2. 会让电脑的 CPU 占用率极轻微地上升（在现代多核CPU上几乎可以忽略不计）。\n 3. 极个别老旧山寨网卡的驱动存在缺陷，关闭这些功能可能导致网卡不稳定，如遇频繁掉线请立即执行本工具的“一键恢复”模式。")
    if askYesNo("是否立即微调这些网卡高级属性？(执行时网络会短暂断开 1-2 秒)") {
        fmt.Println("正在调整网卡属性...")
        
        // 分步执行并直接打印详情
        fmt.Print(" 正在关闭 [中断节流]... ")
        err1 := runPowerShell(`Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -like '*Interrupt*' -or $_.RegistryKeyword -like '*Interrupt*'} | Set-NetAdapterAdvancedProperty -RegistryValue '0'`)
        if err1 != nil {
            fmt.Printf("[失败] 详情: %v\n", err1)
        } else {
            fmt.Println("[成功]")
        }

        fmt.Print(" 正在关闭 [节能以太网]... ")
        err2 := runPowerShell(`Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -like '*Energy*' -or $_.DisplayName -like '*节能*' -or $_.RegistryKeyword -like '*EEE*'} | Set-NetAdapterAdvancedProperty -RegistryValue '0'`)
        if err2 != nil {
            fmt.Printf("[失败] 详情: %v\n", err2)
        } else {
            fmt.Println("[成功]")
        }

        fmt.Print(" 正在关闭 [大发包载卸(LSO)]... ")
        err3 := runPowerShell(`Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -like '*Large Send*' -or $_.DisplayName -like '*大发包*' -or $_.RegistryKeyword -like '*LSO*'} | Set-NetAdapterAdvancedProperty -RegistryValue '0'`)
        if err3 != nil {
            fmt.Printf("[失败] 详情: %v\n", err3)
        } else {
            fmt.Println("[成功]")
        }

        if err1 != nil || err2 != nil || err3 != nil {
            fmt.Println("\n[提示] 局部优化未完全生效，通常是因为您的网卡驱动原生不支持某些高级属性（如无线网卡通常没有LSO等），这属于正常硬件限制。")
        } else {
            fmt.Println("\n[成功] 所有支持的网卡硬件属性已全部优化完毕。")
        }
    }

	fmt.Println("  Done ，感谢使用本程序")
}

func startRollback() {
	fmt.Println("\n--- 开始一键恢复默认网络配置 ---")
	if !askYesNo("您确定要撤销本工具做出的所有更改，恢复到 Windows 默认网络配置吗？") {
		return
	}

	fmt.Println("正在恢复 Nagle 算法（清理注册表）...")
	nagleScript := `
	$path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
	Get-ChildItem $path | ForEach-Object {
		$sub = $_.PSChildName
		Remove-ItemProperty "$path\$sub" -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
		Remove-ItemProperty "$path\$sub" -Name "TCPNoDelay" -ErrorAction SilentlyContinue
	}`
	_ = runPowerShell(nagleScript)

	fmt.Println("正在恢复默认 MTU (1500)...")
	_ = runPowerShell(`Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.CompartmentId -eq 1} | Set-NetIPInterface -NlMtuBytes 1500`)

	fmt.Println("正在移除自定义 QoS 策略...")
	_ = runPowerShell(`Get-NetQosPolicy -Name "GoNetOpt_QoS_*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false`)

	fmt.Println("正在安全重置网卡高级属性 (中断节流、节能、LSO 还原出厂状态)...")
	err1 := runPowerShell(`Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -like '*Interrupt*' -or $_.RegistryKeyword -like '*Interrupt*'} | Reset-NetAdapterAdvancedProperty -Confirm:$false`)
	err2 := runPowerShell(`Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -like '*Energy*' -or $_.DisplayName -like '*节能*' -or $_.RegistryKeyword -like '*EEE*'} | Reset-NetAdapterAdvancedProperty -Confirm:$false`)
	err3 := runPowerShell(`Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -like '*Large Send*' -or $_.DisplayName -like '*大发包*' -or $_.RegistryKeyword -like '*LSO*'} | Reset-NetAdapterAdvancedProperty -Confirm:$false`)

	if err1 != nil || err2 != nil || err3 != nil {
		fmt.Println("\n[提示] 部分网卡属性未能成功重置，可能是驱动没有默认基准配置。")
	} else {
		fmt.Println("\n[成功] 恢复指令已全部安全发送！请重启电脑以彻底还原默认状态。")
	}
}