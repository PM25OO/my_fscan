package lib

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/Common"
)

// PacketCollector 收集 POC 检测过程中的 HTTP 请求/响应数据包
// 使用协程安全的设计，每个目标URL维护一组数据包记录
type PacketCollector struct {
	mu      sync.Mutex
	packets map[string][]Common.PacketData // key: 目标标识(URL), value: 数据包列表
}

// 全局数据包收集器
var globalCollector = &PacketCollector{
	packets: make(map[string][]Common.PacketData),
}

// CapturePacket 捕获一次 HTTP 请求和响应的原始数据
// 仅在启用 -save-pcapng 时才实际执行捕获
func CapturePacket(targetKey string, req *http.Request, resp *Response, rawReqBody []byte) {
	if !Common.SaveHTTPPacket || Common.GlobalPacketSaver == nil {
		return
	}

	// 构建原始请求文本
	rawRequest := buildRawRequest(req, rawReqBody)

	// 构建原始响应文本
	rawResponse := buildRawResponse(resp)

	pkt := Common.PacketData{
		RawRequest:  rawRequest,
		RawResponse: rawResponse,
		TargetURL:   targetKey,
	}

	globalCollector.mu.Lock()
	globalCollector.packets[targetKey] = append(globalCollector.packets[targetKey], pkt)
	globalCollector.mu.Unlock()
}

// FlushPackets 将指定目标的所有捕获数据包保存到文件并清空缓存
// 在漏洞确认后调用
func FlushPackets(targetKey string, vulnName string) {
	if !Common.SaveHTTPPacket || Common.GlobalPacketSaver == nil {
		return
	}

	globalCollector.mu.Lock()
	packets := globalCollector.packets[targetKey]
	delete(globalCollector.packets, targetKey)
	globalCollector.mu.Unlock()

	if len(packets) > 0 {
		Common.SaveVulnPacket(vulnName, packets)
	}
}

// ClearPackets 清空指定目标的数据包缓存(无漏洞时清理)
func ClearPackets(targetKey string) {
	if !Common.SaveHTTPPacket {
		return
	}

	globalCollector.mu.Lock()
	delete(globalCollector.packets, targetKey)
	globalCollector.mu.Unlock()
}

// buildRawRequest 从 http.Request 构建原始 HTTP 请求文本
func buildRawRequest(req *http.Request, body []byte) string {
	if req == nil {
		return ""
	}

	// 尝试使用标准库 dump
	dumped, err := httputil.DumpRequestOut(req, false)
	if err == nil {
		var builder strings.Builder
		builder.Write(dumped)
		if len(body) > 0 {
			builder.Write(body)
		}
		return builder.String()
	}

	// 回退：手动构建
	var builder strings.Builder

	// 请求行
	path := req.URL.RequestURI()
	builder.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, path))

	// Host header
	builder.WriteString(fmt.Sprintf("Host: %s\r\n", req.URL.Host))

	// 其他 Headers
	for key, values := range req.Header {
		for _, value := range values {
			builder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// 空行
	builder.WriteString("\r\n")

	// Body
	if len(body) > 0 {
		builder.Write(body)
	}

	return builder.String()
}

// buildRawResponse 从自定义 Response 构建原始 HTTP 响应文本
func buildRawResponse(resp *Response) string {
	if resp == nil {
		return ""
	}

	var builder strings.Builder

	// 状态行
	statusText := http.StatusText(int(resp.Status))
	if statusText == "" {
		statusText = "Unknown"
	}
	builder.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.Status, statusText))

	// 响应头
	for key, value := range resp.Headers {
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// 空行
	builder.WriteString("\r\n")

	// 响应体 - 限制大小避免过大文件
	body := resp.Body
	const maxBodySize = 256 * 1024 // 256KB
	if len(body) > maxBodySize {
		builder.Write(body[:maxBodySize])
		builder.WriteString(fmt.Sprintf("\n\n... [body truncated, total %d bytes] ...\n", len(body)))
	} else {
		builder.Write(body)
	}

	return builder.String()
}

// DumpRequestBody 从 http.Request 中读取并恢复 body 内容
func DumpRequestBody(req *http.Request) []byte {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	// 读取 body
	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	body := buf.Bytes()

	// 恢复 body 以供后续使用
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	return body
}
