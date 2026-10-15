{{ if and .ClientAddress (ne .ClientAddress "dynamic") -}}
ifconfig-push {{ .ClientAddress }} {{ .Netmask }}
{{ end -}}
{{ if and .ClientAddressIPv6 (ne .ClientAddressIPv6 "dynamic") -}}
ifconfig-ipv6-push {{ .ClientAddressIPv6 }}/{{ .IPv6PrefixLen }}
{{ end -}}
{{ range $route := .CustomRoutes -}}
{{ if $route.IsIPv6 -}}
push "route-ipv6 {{ $route.Address }}/{{ $route.Mask }}"{{ with $route.Description }} # {{ . }}{{ end }}
{{ else -}}
push "route {{ $route.Address }} {{ $route.Mask }}"{{ with $route.Description }} # {{ . }}{{ end }}
{{ end -}}
{{ end -}}
