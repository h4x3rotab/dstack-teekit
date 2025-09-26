#!/bin/sh

systemctl disable --now nginx
rm /etc/nginx/ssl/self.crt /etc/nginx/ssl/self.key /etc/nginx/conf.d/*.conf
