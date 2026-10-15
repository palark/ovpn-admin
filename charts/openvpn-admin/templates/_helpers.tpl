{{/*
IP family settings of the Services: PreferDualStack when openvpn.dualStack is enabled.
*/}}
{{- define "openvpn-admin.ipFamilies" -}}
{{- if .Values.openvpn.dualStack }}
ipFamilyPolicy: PreferDualStack
{{- with .Values.openvpn.ipFamilies }}
ipFamilies:
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}
{{- end }}

{{/*
External IPs for inlet: ExternalIP (openvpn.externalIPs + legacy openvpn.externalIP) as a JSON array.
*/}}
{{- define "openvpn-admin.externalIPs" -}}
{{- $ips := list }}
{{- range .Values.openvpn.externalIPs }}
{{- $ips = append $ips (toString .) }}
{{- end }}
{{- with .Values.openvpn.externalIP }}
{{- $ips = append $ips (toString .) }}
{{- end }}
{{- if not $ips }}
{{- fail "openvpn.externalIPs (or the legacy openvpn.externalIP) is required for inlet: ExternalIP" }}
{{- end }}
{{- uniq $ips | toJson }}
{{- end }}

{{/*
Port of the OpenVPN server for the clients: openvpn.externalPort, else hostPort for inlet: HostPort, else 1194.
*/}}
{{- define "openvpn-admin.externalPort" -}}
{{- $port := 1194 }}
{{- if and (eq (toString .Values.openvpn.inlet) "HostPort") .Values.openvpn.hostPort }}
{{- $port = .Values.openvpn.hostPort }}
{{- end }}
{{- with .Values.openvpn.externalPort }}
{{- $port = . }}
{{- end }}
{{- $port }}
{{- end }}
