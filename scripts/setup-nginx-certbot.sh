#!/bin/sh

# Set up nginx to proxy port 443->3001 with Let's Encrypt, for Ubuntu.
# Usage: ./setup-nginx-domain.sh <hostname>
set -eu

[ $# -eq 1 ] || { echo "Usage: $0 <hostname>" >&2; exit 1; }

HOST="$1"
TOKEN="$(date +%s | md5sum | awk '{print $1}')"

apt-get update -y
APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx dnsutils curl

systemctl enable --now nginx

# Minimal HTTP server block: proxy to app AND expose a readiness token
cat > "/etc/nginx/conf.d/$HOST.conf" <<EOF
server {
  listen 80;
  server_name $HOST;

  # readiness token to confirm DNS+HTTP reachability from the internet
  location = /.well-known/dns-ready.txt {
    default_type text/plain;
    return 200 "$TOKEN\n";
  }

  location / {
    proxy_pass http://127.0.0.1:3001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF

nginx -t
systemctl reload nginx

echo "Waiting for DNS + HTTP reachability for $HOST ..."
attempts=0
while :; do
  attempts=$((attempts + 1))
  # collect a few A records from major public resolvers (no need to know our own IP)
  IPS="$( (dig +short -4 "$HOST" @1.1.1.1; dig +short -4 "$HOST" @8.8.8.8; dig +short -4 "$HOST" @9.9.9.9) 2>/dev/null | sort -u )"

  ok=0
  for ip in $IPS; do
    body="$(curl -fsS --max-time 4 -H "Host: $HOST" "http://$ip/.well-known/dns-ready.txt" || true)"
    if [ "x$body" = "x$TOKEN" ]; then
      ok=1
      break
    fi
  done

  if [ "$ok" -eq 1 ]; then
    echo "✔ DNS is pointing to a host that serves our token."
    break
  fi

  if [ $attempts -ge 120 ]; then
    echo "DNS/HTTP not ready after 10 minutes. Aborting." >&2
    exit 3
  fi

  sleep 5
done

# Obtain & install certificate non-interactively; force HTTPS redirect
certbot --nginx \
  -d "$HOST" \
  --non-interactive --agree-tos --redirect \
  --register-unsafely-without-email

nginx -t
systemctl reload nginx

echo "Done. https://$HOST now proxies to http://127.0.0.1:3001, with certbot auto-renewal."
