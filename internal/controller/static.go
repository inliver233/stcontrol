package controller

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
)

// installSh 嵌入一键安装脚本(编译时打包进二进制)。
//go:embed install.sh
var installSh []byte

// handleInstallScript 分发子控一键安装脚本。
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-sh; charset=utf-8")
	_, _ = w.Write(installSh)
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
			fileServer.ServeHTTP(w, req)
			return
		}
		// SPA 回退
		http.ServeFile(w, req, indexPath)
	})
}
