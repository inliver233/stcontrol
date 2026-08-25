package controller

import (
	_ "embed"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// installSh 嵌入一键安装脚本(编译时打包进二进制)。
//
//go:embed install.sh
var installSh []byte

// handleInstallScript 分发子控一键安装脚本。
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-sh; charset=utf-8")
	_, _ = w.Write(installSh)
}

var agentArtifacts = map[string]string{
	"agent-linux-amd64":        "application/octet-stream",
	"agent-linux-amd64.sha256": "text/plain; charset=utf-8",
	"agent-linux-arm64":        "application/octet-stream",
	"agent-linux-arm64.sha256": "text/plain; charset=utf-8",
}

// handleAgentArtifact serves only the Linux Agent artifacts produced by the
// controller image build. Keeping this route separate from the SPA prevents a
// missing binary from being returned as index.html with a misleading 200.
func (s *Server) handleAgentArtifact(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	contentType, allowed := agentArtifacts[name]
	if !allowed {
		http.NotFound(w, r)
		return
	}
	dir := s.Cfg.AgentDistDir
	if dir == "" {
		dir = "./dist"
	}
	artifactPath := filepath.Join(dir, name)
	info, err := os.Stat(artifactPath)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	if !strings.HasSuffix(name, ".sha256") {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	http.ServeFile(w, r, artifactPath)
}

// mountStatic 挂载 React 前端构建产物（若目录存在），并对 SPA 路由回退到 index.html。
func (s *Server) mountStatic(r *chi.Mux) {
	dir := s.Cfg.StaticDir
	if dir == "" {
		dir = "./web/dist"
	}
	indexPath := filepath.Join(dir, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		// 前端未构建, 仅提供 API
		r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("stcontrol controller API. 前端未构建, 请在 web/ 下执行 npm run build。"))
		})
		return
	}

	fileServer := http.FileServer(http.Dir(dir))
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		path := filepath.Join(dir, filepath.Clean(req.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if filepath.Base(path) == "index.html" {
				s.setSPAContentSecurityPolicy(w, req)
			}
			fileServer.ServeHTTP(w, req)
			return
		}
		// SPA 回退
		s.setSPAContentSecurityPolicy(w, req)
		http.ServeFile(w, req, indexPath)
	})
}

// setSPAContentSecurityPolicy adds only origins derived from durable node
// base URLs. Database or URL validation failures retain the middleware's
// strict self-only policy.
func (s *Server) setSPAContentSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.Store == nil {
		return
	}
	nodes, err := s.Store.ListNodes(r.Context())
	if err != nil {
		return
	}
	baseURLs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node != nil {
			baseURLs = append(baseURLs, node.BaseURL)
		}
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy(nodeConnectSources(baseURLs)))
}

// nodeConnectSources converts node base URLs into deterministic CSP origins.
// Paths, queries and fragments never enter the policy, and credentials or
// non-HTTP schemes fail closed.
func nodeConnectSources(baseURLs []string) []string {
	unique := make(map[string]struct{}, len(baseURLs))
	for _, raw := range baseURLs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
			continue
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "http" {
			continue
		}
		origin := (&url.URL{Scheme: scheme, Host: parsed.Host}).String()
		unique[origin] = struct{}{}
	}
	sources := make([]string, 0, len(unique))
	for source := range unique {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources
}
