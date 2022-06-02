## V2Ray 基于 Nginx 的 vmess+ws+tls 一键安装脚本

感谢[@wulabing](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)分享的脚本。
感谢[@Loyalsoldier](https://github.com/Loyalsoldier/v2ray-rules-dat#geositedat-1)分享的数据和配置。

本脚本使用[官方安装脚本](https://github.com/v2fly/fhs-install-v2ray)安装V2ray并基于[VMess-fAEAD-disable](https://github.com/KukiSa/VMess-fAEAD-disable)保留了MD5兼容

### 安装/更新方式

Vmess+websocket+TLS+Nginx+Website
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/master/install.sh" && chmod +x install.sh && bash install.sh
```

**注意**: 脚本默认使用最新的Core, 请注意客户端 Core 的同步更新，需要保证客户端内核版本 >= 服务端内核版本

### 更新日志

> 更新内容请查看 CHANGELOG.md

### 证书

> 如果你已经拥有了你所使用域名的证书文件，可以将 crt 和 key 文件命名为 v2ray.crt v2ray.key 放在 /data 目录下（若目录不存在请先建目录），请注意证书文件权限及证书有效期，自定义证书有效期过期后请自行续签

脚本支持自动生成 let's encrypted 证书，有效期3个月，理论上自动生成的证书支持自动续签

### 查看客户端配置

```
sudo su -
less ~/v2ray_info.inf
```

### 启动方式

```
启动 V2ray:
systemctl start v2ray

停止 V2ray:
systemctl stop v2ray

启动 Nginx:
systemctl start nginx

停止 Nginx:
systemctl stop nginx
```

### 相关目录

```
Web 目录:
/home/wwwroot

V2ray 服务端配置:
/usr/local/etc/v2ray/config.json

V2ray 客户端配置:
~/v2ray_info.inf

Nginx 目录
/etc/nginx

证书文件: 
/data/v2ray.key
/data/v2ray.crt
```

### 链接
- [acme.sh](https://github.com/acmesh-official/acme.sh)
- [客户端](https://itlanyan.com/v2ray-clients-download/)