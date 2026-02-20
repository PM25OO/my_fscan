package Common

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PacketData 存储单次 HTTP 请求和响应的原始数据
type PacketData struct {
	RawRequest  string // 原始 HTTP 请求文本
	RawResponse string // 原始 HTTP 响应文本
	TargetURL   string // 目标 URL
	Timestamp   time.Time
}

// PacketSaver 负责将 HTTP 请求/响应包保存到本地文件
type PacketSaver struct {
	mu        sync.Mutex
	outputDir string
}

// 全局数据包保存器实例
var GlobalPacketSaver *PacketSaver

// InitPacketSaver 初始化数据包保存器
func InitPacketSaver() error {
	if !SaveHTTPPacket {
		return nil
	}

	dir := PacketOutputDir
	if dir == "" {
		dir = "packets"
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf(GetText("packet_init_dir_failed", err))
	}

	GlobalPacketSaver = &PacketSaver{
		outputDir: dir,
	}

	LogBase(GetText("packet_init_success", dir))
	return nil
}

// SaveVulnPacket 保存漏洞触发时的 HTTP 请求/响应包
// vulnName: 漏洞名称
// packets: 该漏洞触发过程中所有的请求/响应包
func SaveVulnPacket(vulnName string, packets []PacketData) {
	if GlobalPacketSaver == nil || !SaveHTTPPacket {
		return
	}
	GlobalPacketSaver.savePackets(vulnName, packets)
}

// SaveSinglePacket 保存单个漏洞请求/响应包(简化接口)
func SaveSinglePacket(vulnName string, packet PacketData) {
	SaveVulnPacket(vulnName, []PacketData{packet})
}

// savePackets 将数据包列表写入文件
func (ps *PacketSaver) savePackets(vulnName string, packets []PacketData) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if len(packets) == 0 {
		return
	}

	// 生成安全的文件名
	fileName := ps.generateFileName(vulnName, packets[0].TargetURL)
	filePath := filepath.Join(ps.outputDir, fileName)

	// 构建文件内容
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("# 漏洞数据包记录\n"))
	builder.WriteString(fmt.Sprintf("# Vulnerability Packet Capture\n"))
	builder.WriteString(fmt.Sprintf("# ================================\n"))
	builder.WriteString(fmt.Sprintf("# 漏洞名称 (Vuln Name): %s\n", vulnName))
	builder.WriteString(fmt.Sprintf("# 目标 (Target): %s\n", packets[0].TargetURL))
	builder.WriteString(fmt.Sprintf("# 时间 (Time): %s\n", time.Now().Format("2006-01-02 15:04:05")))
	builder.WriteString(fmt.Sprintf("# 请求/响应数量 (Packet Count): %d\n", len(packets)))
	builder.WriteString("# ================================\n\n")

	for i, pkt := range packets {
		if len(packets) > 1 {
			builder.WriteString(fmt.Sprintf("========== 第 %d/%d 个请求/响应 (Packet %d/%d) ==========\n\n", i+1, len(packets), i+1, len(packets)))
		}

		// 写入请求
		builder.WriteString(">>>>>>>>>> HTTP REQUEST >>>>>>>>>>\n\n")
		builder.WriteString(pkt.RawRequest)
		if !strings.HasSuffix(pkt.RawRequest, "\n") {
			builder.WriteString("\n")
		}
		builder.WriteString("\n")

		// 写入响应
		builder.WriteString("<<<<<<<<<< HTTP RESPONSE <<<<<<<<<<\n\n")
		builder.WriteString(pkt.RawResponse)
		if !strings.HasSuffix(pkt.RawResponse, "\n") {
			builder.WriteString("\n")
		}
		builder.WriteString("\n")

		if len(packets) > 1 {
			builder.WriteString("\n")
		}
	}

	// 写入文件
	if err := os.WriteFile(filePath, []byte(builder.String()), 0644); err != nil {
		LogError(fmt.Sprintf(GetText("packet_save_failed", filePath, err)))
		return
	}

	LogBase(fmt.Sprintf(GetText("packet_save_success", filePath)))
}

// generateFileName 生成安全的文件名
func (ps *PacketSaver) generateFileName(vulnName string, targetURL string) string {
	// 从 URL 中提取主机和端口
	hostPart := "unknown"
	if targetURL != "" {
		if u, err := url.Parse(targetURL); err == nil {
			hostPart = u.Hostname()
			if port := u.Port(); port != "" {
				hostPart += "_" + port
			}
		}
	}

	// 清理漏洞名称，只保留安全字符
	safeName := sanitizeFileName(vulnName)
	if len(safeName) > 80 {
		safeName = safeName[:80]
	}

	// 时间戳
	timestamp := time.Now().Format("20060102_150405")

	return fmt.Sprintf("%s_%s_%s.txt", safeName, hostPart, timestamp)
}

// sanitizeFileName 移除文件名中不安全的字符
func sanitizeFileName(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}
