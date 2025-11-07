package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// Embed static assets
//
//go:embed static/*
var StaticAssets embed.FS

// Embed templates
//
//go:embed templates/*
var TemplateAssets embed.FS

// GetStaticFS returns the embedded static filesystem
func GetStaticFS() fs.FS {
	static, err := fs.Sub(StaticAssets, "static")
	if err != nil {
		panic(err)
	}
	return static
}

// GetTemplateFS returns the embedded template filesystem
func GetTemplateFS() fs.FS {
	templates, err := fs.Sub(TemplateAssets, "templates")
	if err != nil {
		panic(err)
	}
	return templates
}

// NewStaticHandler creates an HTTP handler for serving static assets
func NewStaticHandler() http.Handler {
	return http.FileServer(http.FS(GetStaticFS()))
}

// GetTemplatePath returns the path for a given template file
func GetTemplatePath(templateName string) string {
	return "web/templates/" + templateName
}
