package handler

import (
	"net/http"
	"os"
	"path"
	"strings"
)

// DocsHandler serves API documentation
type DocsHandler struct{}

// NewDocsHandler creates a new documentation handler
func NewDocsHandler() *DocsHandler {
	return &DocsHandler{}
}

// RegisterRoutes registers documentation routes
func (h *DocsHandler) RegisterRoutes(mux *http.ServeMux) {
	// Serve OpenAPI specification
	mux.HandleFunc("/api/openapi.yaml", h.handleOpenAPISpec)
	mux.HandleFunc("/api/openapi.json", h.handleOpenAPISpecJSON)

	// Serve Swagger UI
	mux.HandleFunc("/docs", h.handleSwaggerRedirect)
	mux.HandleFunc("/docs/", h.handleSwaggerUI)

	// Serve static assets for Swagger UI
	mux.HandleFunc("/docs/static/", h.handleSwaggerStatic)
}

// handleOpenAPISpec serves the OpenAPI YAML specification
func (h *DocsHandler) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set cache headers for API spec
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Cache-Control", "public, max-age=300") // 5 minutes

	// Read the OpenAPI spec file from filesystem
	spec, err := os.ReadFile("api/openapi.yaml")
	if err != nil {
		http.Error(w, "API specification not found", http.StatusNotFound)
		return
	}

	w.Write(spec)
}

// handleOpenAPISpecJSON serves the OpenAPI JSON specification
func (h *DocsHandler) handleOpenAPISpecJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // 5 minutes

	// For now, redirect to YAML (in a real implementation, you'd convert YAML to JSON)
	http.Error(w, "JSON format not yet implemented, use /api/openapi.yaml", http.StatusNotImplemented)
}

// handleSwaggerRedirect redirects /docs to /docs/
func (h *DocsHandler) handleSwaggerRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
}

// handleSwaggerUI serves the Swagger UI interface
func (h *DocsHandler) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set cache headers
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600") // 1 hour

	// Serve embedded Swagger UI HTML
	html := h.generateSwaggerHTML()
	w.Write([]byte(html))
}

// handleSwaggerStatic serves static assets for Swagger UI
func (h *DocsHandler) handleSwaggerStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract file path
	filePath := strings.TrimPrefix(r.URL.Path, "/docs/static/")

	// Set appropriate content type
	ext := path.Ext(filePath)
	switch ext {
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	// Set cache headers for static assets
	w.Header().Set("Cache-Control", "public, max-age=86400") // 24 hours

	// For now, just return 404 for static files (in production, you'd serve actual files)
	http.Error(w, "Static files not implemented", http.StatusNotFound)
}

// generateSwaggerHTML generates the Swagger UI HTML page
func (h *DocsHandler) generateSwaggerHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Go-Lock API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        
        *, *:before, *:after {
            box-sizing: inherit;
        }

        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/openapi.yaml',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true,
                requestInterceptor: function(request) {
                    // Add any custom headers or modify requests here
                    return request;
                },
                responseInterceptor: function(response) {
                    // Handle responses here
                    return response;
                }
            });
        };
    </script>
</body>
</html>`
}
