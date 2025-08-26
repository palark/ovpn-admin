{{- range $server := .Hosts }}
remote {{ $server.Host }} {{ $server.Port }} {{ $server.Protocol }}
{{- end }}

# -- General Settings -- #

verb 4
client
nobind
dev tun

# -- Security & Encryption -- #

cipher AES-256-GCM
key-direction 1
tls-client
remote-cert-tls server

# uncomment below line if want to redirect all trafic from vpn 
# redirect-gateway def1  

# -- DNS Handing -- #

# uncomment below lines for use with linux

#script-security 2
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf

# if you use systemd-resolved first install openvpn-systemd-resolved package
#up /etc/openvpn/update-systemd-resolved
#down /etc/openvpn/update-systemd-resolved


{{- if .PasswdAuth }}
auth-user-pass
{{- end }}

<cert>
{{ .Cert -}}
</cert>
<key>
{{ .Key -}}
</key>
<ca>
{{ .CA -}}
</ca>
<tls-auth>
{{ .TLS -}}
</tls-auth>
