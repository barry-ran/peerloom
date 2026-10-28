// Package adminweb serves the built, same-origin administrator UI. No runtime
// templates, remote scripts, credentials, or arbitrary filesystem paths are used.
package adminweb

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed assets/*
var assets embed.FS

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		if strings.Contains(r.URL.EscapedPath(), "%") {
			http.NotFound(w, r)
			return
		}
		var name, mime string
		switch r.URL.Path {
		case "/admin", "/admin/":
			name = "index.html"
			mime = "text/html; charset=utf-8"
		case "/admin/assets/app.js":
			name = "app.js"
			mime = "text/javascript; charset=utf-8"
		case "/admin/assets/style.css":
			name = "style.css"
			mime = "text/css; charset=utf-8"
		default:
			http.NotFound(w, r)
			return
		}
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			http.Error(w, "asset unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", mime)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}
