## V2Ray 基于 Nginx 的 vmess+ws+tls 一键安装脚本

本脚本使用[社区安装脚本](https://github.com/v2fly/fhs-install-v2ray)安装V2ray并基于[VMess-fAEAD-disable](https://github.com/KukiSa/VMess-fAEAD-disable)保留了MD5兼容

- 感谢[@wulabing](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)分享的脚本。
- 感谢[@Loyalsoldier](https://github.com/Loyalsoldier/v2ray-rules-dat#geositedat-1)分享的数据和配置 - JSON
- 感谢[@Loyalsoldier](https://github.com/Loyalsoldier/clash-rules)分享的数据和配置 - YAML。

### 安装/更新方式

Vmess+websocket+TLS+Nginx+Website
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/master/install.sh" && chmod +x install.sh && bash install.sh
```

**注意**: 
1. 脚本默认使用最新的Core, 请注意客户端 Core 的同步更新，需要保证客户端内核版本 >= 服务端内核版本
2. 确保入站80端口和自己所需的端口已经打开. 比如使用微软的云服务，NSG需要允许所需端口.
3. 由于 [websocket: close 1000 (normal) > proxy/vmess/encoding: invalid user > proxy/vmess: Not Found](https://github.com/v2fly/v2ray-core/issues/1605), 使用固定的v2ray社区安转脚本(commit: 224e431). 如果问题解决, 可自行升级最新社区安装脚本
4. 使用yaml配置文件的时候(针对ClashX Pro), 需要把ruleset里的配置文件一起保存到本地

### 更新日志

> 更新内容请查看 CHANGELOG.md

### 证书

> 如果你已经拥有了你所使用域名的证书文件，可以将 crt 和 key 文件命名为 v2ray.crt v2ray.key 放在 /data 目录下（若目录不存在请先建目录），请注意证书文件权限及证书有效期，自定义证书有效期过期后请自行续签

脚本支持自动生成 let's encrypted 证书，有效期3个月，理论上自动生成的证书支持自动续签

### 查看客户端配置

```
less /usr/local/v2ray/client_config.json
less /usr/local/v2ray/client_config.yaml
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
/usr/local/v2ray/client_config.json
/usr/local/v2ray/client_config.yaml

ClashX Pro 规则目录:
/usr/local/v2ray/ruleset

Nginx 目录
/etc/nginx

证书文件: 
/data/v2ray.key
/data/v2ray.crt
```

### 链接
- [v2ray](https://www.v2ray.com)
- [v2fly](https://www.v2fly.org/)
- [acme.sh](https://github.com/acmesh-official/acme.sh)
- [ClashX](https://github.com/yichengchen/clashX) 
  - [Doc1](https://github.com/Dreamacro/clash/wiki/Configuration)
  - [Doc2](https://lancellc.gitbook.io/clash/clash-config-file/dns)
- [客户端](https://itlanyan.com/v2ray-clients-download/)