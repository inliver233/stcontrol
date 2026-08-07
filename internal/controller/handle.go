package controller

import (
	"regexp"
	"strings"
)

var nonHandleChars = regexp.MustCompile(`[^a-z0-9-]`)
var multiDash = regexp.MustCompile(`-+`)

// NormalizeHandle 与酒馆 users.js 的 normalizeHandle 完全一致：
// 小写、去首尾空格、非法字符替换为横杠、合并连续横杠、去首尾横杠。
func NormalizeHandle(h string) string {
	if h == "" {
		return ""
	}
	h = strings.ToLower(h)
	h = strings.TrimSpace(h)
	h = nonHandleChars.ReplaceAllString(h, "-")
	h = multiDash.ReplaceAllString(h, "-")
	h = strings.Trim(h, "-")
	return h
}

// isValidHandle 校验规范化后的 handle（仅字母数字横杠，长度合理）。
func isValidHandle(h string) bool {
	if len(h) < 3 || len(h) > 32 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
