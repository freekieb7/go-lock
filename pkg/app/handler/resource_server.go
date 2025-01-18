package handler

import (
	"html/template"
	"net/http"

	"github.com/freekieb7/go-lock/pkg/core/data/store"
	"github.com/freekieb7/go-lock/pkg/core/settings"
)

func ResourceServer(settings *settings.Settings, resourceServer *store.ResourceServerStore) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				resourceServers, err := resourceServer.All(r.Context(), 10, 0)
				if err != nil {
					panic(err)
				}

				tmpl, err := template.ParseFiles("template/base.html", "template/component/sidebar.html", "template/resource_servers.html")
				if err != nil {
					panic(err)
				}

				resourceServersData := make([]map[string]any, len(resourceServers))
				for idx, resourceServer := range resourceServers {
					resourceServersData[idx] = map[string]any{
						"Id":   resourceServer.Id,
						"Name": resourceServer.Name,
						"Url":  resourceServer.Url,
						"Type": resourceServer.Type.UserFriendlyName(),
					}
				}

				tmpl.Execute(w, map[string]any{
					"ResourceServers": resourceServersData,
				})
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
		},
	)
}
