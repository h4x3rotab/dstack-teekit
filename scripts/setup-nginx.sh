#!/bin/sh

# Set up nginx to proxy port 443->3001 with self-signed HTTPS
sudo apt update && sudo apt install -y nginx openssl
sudo mkdir -p /etc/nginx/ssl && sudo openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=$(hostname)" -keyout /etc/nginx/ssl/self.key -out /etc/nginx/ssl/self.crt
sudo tee /etc/nginx/conf.d/https-3000-proxy.conf >/dev/null <<'EOF'
server {
  listen 443 ssl http2;
  server_name _;
  ssl_certificate /etc/nginx/ssl/self.crt;
  ssl_certificate_key /etc/nginx/ssl/self.key;

  location / {
    proxy_pass http://127.0.0.1:3001;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
server {
  listen 80;
  server_name _;
  return 301 https://$host$request_uri;
}
EOF
sudo nginx -t && sudo systemctl reload nginx
