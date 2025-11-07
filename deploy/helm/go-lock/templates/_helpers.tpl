{{/*
Expand the name of the chart.
*/}}
{{- define "go-lock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "go-lock.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "go-lock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "go-lock.labels" -}}
helm.sh/chart: {{ include "go-lock.chart" . }}
{{ include "go-lock.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "go-lock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "go-lock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "go-lock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "go-lock.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create base URL from ingress configuration
*/}}
{{- define "go-lock.baseURL" -}}
{{- if .Values.server.baseURL }}
{{- .Values.server.baseURL }}
{{- else if .Values.ingress.enabled }}
{{- $host := index .Values.ingress.hosts 0 }}
{{- if .Values.ingress.tls }}
{{- printf "https://%s" $host.host }}
{{- else }}
{{- printf "http://%s" $host.host }}
{{- end }}
{{- else }}
{{- printf "http://localhost:%d" (.Values.server.port | int) }}
{{- end }}
{{- end }}