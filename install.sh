#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

# Fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

# Notification information
INFO="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

# 版本
shell_version="2.0.0"
shell_mode="None"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
v2ray_conf_dir="/usr/local/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
v2ray_bin_dir="/usr/local/bin"
v2ray_client_dir="/usr/local/v2ray"
v2ray_client_config_json="${v2ray_client_dir}/client_config.json"
v2ray_client_config_yaml="${v2ray_client_dir}/client_config.yaml"
v2ray_client_config_yaml_ruleset="${v2ray_client_dir}/ruleset"
nginx_systemd_file="/etc/systemd/system/nginx.service"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
v2ray_log_dir="/var/log/v2ray"
v2ray_access_log="${v2ray_log_dir}/access.log"
v2ray_error_log="${v2ray_log_dir}/error.log"
v2ray_dat_path="/usr/local/share/v2ray/"
v2ray_ssl_path="/data"
v2ray_ssl_key="${v2ray_ssl_path}/v2ray.key"
v2ray_ssl_crt="${v2ray_ssl_path}/v2ray.crt"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="/usr/local/bin/ssl_update.sh"
nginx_version="1.20.1"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"

#简易随机数
random_num=$((RANDOM%12+4))
#生成伪装路径
camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

source '/etc/os-release'
#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## 添加 Nginx apt源
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    $INS install dbus

    if [[ $(which firewalld) ]]; then
        systemctl stop firewalld
        systemctl disable firewalld
        echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"
    fi

    if [[ $(which ufw) ]]; then
        systemctl stop ufw
        systemctl disable ufw
        echo -e "${OK} ${GreenBG} ufw 已关闭 ${Font}"
    fi
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}

chrony_install() {
    ${INS} -y install chrony
    judge "安装 chrony 时间同步服务 "

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd 启动 "

    timedatectl set-timezone Asia/Shanghai

    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -rp "请确认时间是否准确,误差范围±3分钟(Y/N): " chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
    [yY][eE][sS] | [yY])
        echo -e "${GreenBG} 继续安装 ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} 安装终止 ${Font}"
        exit 2
        ;;
    esac
}

dependency_install() {
    ${INS} install wget git lsof -y

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置 "

    ${INS} -y install bc
    judge "安装 bc"

    ${INS} -y install unzip
    judge "安装 unzip"

    ${INS} -y install qrencode
    judge "安装 qrencode"

    ${INS} -y install curl
    judge "安装 curl"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y groupinstall "Development tools"
    else
        ${INS} -y install build-essential
    fi
    judge "编译工具包 安装"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install pcre pcre-devel zlib-devel epel-release
    else
        ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
    fi

    ${INS} -y install haveged
    judge "haveged 安装"

    if [[ "${ID}" == "centos" ]]; then
        systemctl start haveged && systemctl enable haveged
        judge "haveged 启动"
    else
        systemctl start haveged && systemctl enable haveged
        judge "haveged 启动"
    fi

    mkdir -p /usr/local/bin >/dev/null 2>&1
}

basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

port_alterid_set() {
    read -rp "请输入连接端口（default:443）:" port
    [[ -z ${port} ]] && port="443"
    echo -e "${INFO} ${GreenBG} 是否开启VMess MD5 认证信息兼容 (y/n) ${Font}"
    read -r enableMD5
    case $enableMD5 in
    [yY][eE][sS] | [yY])
        read -rp "请输入alterID（default:2 仅允许填非0数字）:" alterID
        [[ -z ${alterID} ]] && alterID="2"
        ;;
    *)
        alterID="0"
        ;;
    esac
}

modify_path() {
    sed -i "/\"path\"/c \\\t  \"path\":\"${camouflage}\"" ${v2ray_conf}
    sed -i "99c \"path\": \"${camouflage}\"," "${v2ray_client_config_json}"
    sed -i "60c \ \ \ \ path: ${camouflage}" "${v2ray_client_config_yaml}"
    judge "V2ray 伪装路径 修改"
}

modify_alterid() {
    # https://github.com/KukiSa/VMess-fAEAD-disable
    if [[ "${alterID}" -eq 0 ]]; then
        sed -i '/Environment="V2RAY_VMESS_AEAD_FORCED=false"/d' "${v2ray_systemd_file}"
        echo -e "${OK} ${GreenBG} 禁用VMess MD5 认证信息兼容 ${Font}"
    else
        sed -i '/Environment="V2RAY_VMESS_AEAD_FORCED=false"/d' "${v2ray_systemd_file}"
        sed -i '/ExecStart/i\Environment="V2RAY_VMESS_AEAD_FORCED=false"' "${v2ray_systemd_file}"
        echo -e "${OK} ${GreenBG} 启用VMess MD5 认证信息兼容 ${Font}"
    fi

    sed -i "/\"alterId\"/c \\\t  \"alterId\":${alterID}" ${v2ray_conf}
    sed -i "86c \"alterId\": ${alterID}," "${v2ray_client_config_json}"
    sed -i "52c \ \ alterId: ${alterID}" "${v2ray_client_config_yaml}"
    judge "V2ray alterid 修改"
    echo -e "${OK} ${GreenBG} alterID:${alterID} ${Font}"
}

modify_inbound_port() {
    PORT=$((RANDOM + 10000))
    sed -i "/\"port\"/c  \    \"port\":${PORT}," ${v2ray_conf}
    judge "V2ray inbound_port 修改"
}

modify_UUID() {
    [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    sed -i "/\"id\"/c \\\t  \"id\":\"${UUID}\"," ${v2ray_conf}
    sed -i "85c \"id\": \"${UUID}\"," "${v2ray_client_config_json}"
    sed -i "51c \ \ uuid: ${UUID}" "${v2ray_client_config_yaml}"
    judge "V2ray UUID 修改"
    echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
}

modify_nginx_port() {
    sed -i "/ssl http2;$/c \\\tlisten ${port} ssl http2;" ${nginx_conf}
    sed -i "3c \\\tlisten [::]:${port} http2;" ${nginx_conf}
    sed -i "82c \"port\": ${port}," "${v2ray_client_config_json}"
    sed -i "50c \ \ port: ${port}" "${v2ray_client_config_yaml}"
    judge "V2ray port 修改"
    echo -e "${OK} ${GreenBG} 端口号:${port} ${Font}"
}

modify_nginx_other() {
    sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
    sed -i "/location/c \\\tlocation ${camouflage}" ${nginx_conf}
    sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    sed -i "/return/c \\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
}

web_camouflage() {
    ##请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    rm -rf /home/wwwroot
    mkdir -p /home/wwwroot
    cd /home/wwwroot || exit
    wget --no-check-certificate https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/index.html
    judge "web 站点伪装"
}

v2ray_install() {
    if [[ -d /root/v2ray ]]; then
        rm -rf /root/v2ray
    fi
    if [[ -d /etc/v2ray ]]; then
        rm -rf /etc/v2ray
    fi
    mkdir -p /root/v2ray
    cd /root/v2ray || exit
    wget --no-check-certificate "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/v2fly_224e431/install-release.sh"

    if [[ -f install-release.sh ]]; then
        rm -rf $v2ray_systemd_file
        systemctl daemon-reload
        bash install-release.sh
        judge "安装 V2ray"
    else
        echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
        exit 4
    fi
    # 清除临时文件
    rm -rf /root/v2ray
}

v2ray_update_dat() {
    mkdir -p "${v2ray_dat_path}"
    cd "${v2ray_dat_path}" || exit
    rm -f *.dat
    wget -N --no-check-certificate "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    wget -N --no-check-certificate "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    echo -e "${OK} ${GreenBG} 更新Dat ${Font}"

    mkdir -p "${v2ray_client_config_yaml_ruleset}"
    cd "${v2ray_client_config_yaml_ruleset}" || exit
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"  -O "${v2ray_client_config_yaml_ruleset}/reject.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt" -O "${v2ray_client_config_yaml_ruleset}/icloud.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt" -O "${v2ray_client_config_yaml_ruleset}/apple.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt" -O "${v2ray_client_config_yaml_ruleset}/google.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt" -O "${v2ray_client_config_yaml_ruleset}/proxy.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt" -O "${v2ray_client_config_yaml_ruleset}/direct.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt" -O "${v2ray_client_config_yaml_ruleset}/private.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt" -O "${v2ray_client_config_yaml_ruleset}/gfw.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt" -O "${v2ray_client_config_yaml_ruleset}/greatfire.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt" -O "${v2ray_client_config_yaml_ruleset}/tld-not-cn.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt" -O "${v2ray_client_config_yaml_ruleset}/telegramcidr.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt" -O "${v2ray_client_config_yaml_ruleset}/cncidr.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt" -O "${v2ray_client_config_yaml_ruleset}/lancidr.yaml"
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt" -O "${v2ray_client_config_yaml_ruleset}/applications.yaml"
    echo -e "${OK} ${GreenBG} 更新ruleset ${Font}"
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        echo -e "${OK} ${GreenBG} Nginx已存在，跳过编译安装过程 ${Font}"
        sleep 2
    elif [[ -d "/usr/local/nginx/" ]]; then
        echo -e "${OK} ${GreenBG} 检测到其他套件安装的Nginx，继续安装会造成冲突，请处理后安装${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx 下载"
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl 下载"
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "jemalloc 下载"

    cd ${nginx_openssl_src} || exit

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 jemalloc ${Font}"
    sleep 2

    cd jemalloc-${jemalloc_version} || exit
    ./configure
    judge "编译检查"
    make -j "${THREAD}" && make install
    judge "jemalloc 编译安装"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx, 过程稍久，请耐心等待 ${Font}"
    sleep 4

    cd ../nginx-${nginx_version} || exit

    ./configure --prefix="${nginx_dir}" \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-pcre \
        --with-http_realip_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_secure_link_module \
        --with-http_v2_module \
        --with-cc-opt='-O3' \
        --with-ld-opt="-ljemalloc" \
        --with-openssl=../openssl-"$openssl_version"
    judge "编译检查"
    make -j "${THREAD}" && make install
    judge "Nginx 编译安装"

    # 修改基本配置
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    # 删除临时文件
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # 添加配置文件夹，适配旧版脚本
    mkdir ${nginx_dir}/conf/conf.d
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}

domain_check() {
    read -rp "请输入你的域名信息:" domain
    domain_ip=$(curl -sm8 https://ipget.net/?ip="${domain}")
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
        # 关闭wgcf-warp，以防误判VPS IP情况
        wg-quick down wgcf >/dev/null 2>&1
        echo -e "${OK} ${GreenBG} 已关闭 wgcf-warp ${Font}"
    fi
    local_ipv4=$(curl -s4m8 https://ip.gs)
    local_ipv6=$(curl -s6m8 https://ip.gs)
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        echo -e nameserver 2a01:4f8:c2c:123f::1 > /etc/resolv.conf
        echo -e "${OK} ${GreenBG} VM 只启用了 IPv6, 自动添加 DNS64 服务器 ${Font}"
    fi
    echo -e "域名 DNS 解析到的的 IP：${domain_ip}"
    echo -e "本机IPv4: ${local_ipv4}"
    echo -e "本机IPv6: ${local_ipv6}"
    sleep 2
    if [[ ${domain_ip} == ${local_ipv4} ]]; then
        echo -e "${OK} ${GreenBG} 域名 DNS 解析 IP 与 本机 IPv4 匹配 ${Font}"
        sleep 2
    elif [[ ${domain_ip} == ${local_ipv6} ]]; then
        echo -e "${OK} ${GreenBG} 域名 DNS 解析 IP 与 本机 IPv6 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A / AAAA 记录，否则将无法正常使用 V2ray ${Font}"
        echo -e "${Error} ${RedBG} 域名 DNS 解析 IP 与 本机 IPv4 / IPv6 不匹配 是否继续安装？（y/n）${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}
acme() {
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        echo -e "${OK} ${GreenBG} SSL 证书测试签发成功，开始正式签发 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        sleep 2
    else
        echo -e "${Error} ${RedBG} SSL 证书测试签发失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        sleep 2
        mkdir "${v2ray_ssl_path}"
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${v2ray_ssl_crt}" --keypath "${v2ray_ssl_key}" --ecc --force; then
            echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
            sleep 2
            if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
                wg-quick up wgcf >/dev/null 2>&1
                echo -e "${OK} ${GreenBG} 已启动 wgcf-warp ${Font}"
            fi
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
                wg-quick up wgcf >/dev/null 2>&1
                echo -e "${OK} ${GreenBG} 已启动 wgcf-warp ${Font}"
            fi
        exit 1
    fi
}

v2ray_conf_add_tls() {
    mkdir -p "${v2ray_client_dir}"
    cd "${v2ray_conf_dir}" || exit
    wget --no-check-certificate https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/tls/server_config.json -O config.json
    wget --no-check-certificate https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/tls/client_config.json -O "${v2ray_client_config_json}"
    wget --no-check-certificate https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/tls/client_config.yaml -O "${v2ray_client_config_yaml}"
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
    sed -i "s/test.domain/${domain}/g" "${v2ray_client_config_json}"
    sed -i "s/test.domain/${domain}/g" "${v2ray_client_config_yaml}"
}

nginx_conf_add() {
    touch ${nginx_conf_dir}/v2ray.conf
    cat >${nginx_conf_dir}/v2ray.conf <<EOF
    server {
        listen 443 ssl http2;
        listen [::]:443 http2;
        ssl_certificate       ${v2ray_ssl_crt};
        ssl_certificate_key   ${v2ray_ssl_key};
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           serveraddr.com;
        index index.html index.htm;
        root  /home/wwwroot;
        error_page 400 = /400.html;

        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";

        location /ray/
        {
        proxy_redirect off;
        proxy_read_timeout 1200s;
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;

        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data \$ssl_early_data;
        }
}
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    modify_nginx_port
    modify_nginx_other
    judge "Nginx 配置修改"

}

start_process_systemd() {
    systemctl daemon-reload
    systemctl restart nginx
    judge "Nginx 启动"
    systemctl restart v2ray
    judge "V2ray 启动"
}

enable_process_systemd() {
    systemctl enable v2ray
    judge "设置 v2ray 开机自启"
    systemctl enable nginx
    judge "设置 Nginx 开机自启"
}

stop_process_systemd() {
    systemctl stop nginx
    systemctl stop v2ray
}

nginx_process_disabled() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

acme_cron_update() {
    wget -N -P /usr/local/bin --no-check-certificate "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/ssl_update.sh"
    if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
      if [[ "${ID}" == "centos" ]]; then
          sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
      else
          sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
      fi
    fi
    judge "cron 计划任务更新"
}

info_extraction() {
    grep "$1" $v2ray_client_config_json | awk -F '"' '{print $4}'
}

ssl_judge_and_install() {
    if [[ -f "${v2ray_ssl_key}" || -f "${v2ray_ssl_crt}" ]]; then
        echo "${v2ray_ssl_path} 目录下证书文件已存在"
        echo -e "${OK} ${GreenBG} 是否删除 [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
            [yY][eE][sS] | [yY])
                rm -rf /data/*
                echo -e "${OK} ${GreenBG} 已删除 ${Font}"
                ;;
            *) ;;
        esac
    fi

    if [[ -f "${v2ray_ssl_key}" || -f "${v2ray_ssl_crt}" ]]; then
        echo "证书文件已存在"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "证书文件已存在"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${v2ray_ssl_crt}" --keypath "${v2ray_ssl_key}" --ecc
        judge "证书应用"
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd ServerFile 添加"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]]; then
        echo "请选择支持的 TLS 版本（default:3）:"
        echo "请注意,如果你使用 Quantaumlt X / 路由器 / 旧版 Shadowrocket / 低于 4.18.1 版本的 V2ray core 请选择 兼容模式"
        echo "1: TLS1.1 TLS1.2 and TLS1.3（兼容模式）"
        echo "2: TLS1.2 and TLS1.3 (兼容模式)"
        echo "3: TLS1.3 only"
        read -rp "请输入：" tls_version
        [[ -z ${tls_version} ]] && tls_version=3
        if [[ $tls_version == 3 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.1 TLS1.2 and TLS1.3 ${Font}"
        else
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.2 and TLS1.3 ${Font}"
        fi
        systemctl restart nginx
        judge "Nginx 重启"
    else
        echo -e "${Error} ${RedBG} Nginx 或 配置文件不存在 ${Font}"
    fi
}

show_access_log() {
    [ -f ${v2ray_access_log} ] && tail -f ${v2ray_access_log} || echo -e "${RedBG}log文件不存在${Font}"
}

show_error_log() {
    [ -f ${v2ray_error_log} ] && tail -f ${v2ray_error_log} || echo -e "${RedBG}log文件不存在${Font}"
}

ssl_update_manuel() {
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e "${RedBG}证书签发工具不存在，请确认你是否使用了自己的证书${Font}"
    domain="$(info_extraction '\"host\":')"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${v2ray_ssl_crt}" --keypath "${v2ray_ssl_key}" --ecc
}

bbr_boost_sh() {
    [ -f "bbr.sh" ] && rm -rf ./bbr.sh
    wget -N --no-check-certificate "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/bbr/bbr.sh" && chmod +x bbr.sh && ./bbr.sh
}

bbr_boost_sh_2() {
    [ -f "bbr2.sh" ] && rm -rf ./bbr2.sh
    wget -N --no-check-certificate "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/bbr/bbr2.sh" && chmod +x bbr2.sh && ./bbr2.sh
}

mtproxy_sh() {
    echo -e "${Error} ${RedBG} 功能维护，暂不可用 ${Font}"
}

uninstall_all() {
    stop_process_systemd
    [[ -f $v2ray_systemd_file ]] && rm -f $v2ray_systemd_file
    [[ -d $v2ray_bin_dir ]] && rm -rf $v2ray_bin_dir
    if [[ -d $nginx_dir ]]; then
        echo -e "${OK} ${Green} 是否卸载 Nginx [Y/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            rm -rf $nginx_dir
            rm -rf $nginx_systemd_file
            echo -e "${OK} ${Green} 已卸载 Nginx ${Font}"
            ;;
        *) ;;

        esac
    fi
    [[ -d $v2ray_conf_dir ]] && rm -rf $v2ray_conf_dir
    [[ -d $web_dir ]] && rm -rf $web_dir
    [[ -d $v2ray_log_dir ]] && rm -rf $v2ray_log_dir
    [[ -d $v2ray_client_dir ]] && rm -rf $v2ray_client_dir
    [[ -d $v2ray_dat_path ]] && rm -rf $v2ray_dat_path
    echo -e "${OK} ${Green} 是否卸载acme.sh及证书 [Y/N]? ${Font}"
    read -r uninstall_acme
    case $uninstall_acme in
    [yY][eE][sS] | [yY])
      /root/.acme.sh/acme.sh --uninstall
      rm -rf /root/.acme.sh
      rm -rf /data/*
      ;;
    *) ;;
    esac
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} 已卸载 ${Font}"
}
delete_tls_key_and_crt() {
    [[ -f $HOME/.acme.sh/acme.sh ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d $HOME/.acme.sh ]] && rm -rf "$HOME/.acme.sh"
    echo -e "${OK} ${GreenBG} 已清空证书遗留文件 ${Font}"
}

install_v2ray_ws_tls() {
    is_root
    check_system
    chrony_install
    dependency_install
    basic_optimization
    domain_check
    port_alterid_set
    v2ray_install
    v2ray_update_dat
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    v2ray_conf_add_tls
    nginx_conf_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    tls_type
    start_process_systemd
    enable_process_systemd
    acme_cron_update
    restart_firewall
    notify_users
}

notify_users() {
    echo -e "${INFO} ${GreenBG} 客户端配置: ${v2ray_client_config_json} ${Font}"
    echo -e "${INFO} ${GreenBG} 客户端配置: ${v2ray_client_config_yaml} ${Font}"
    echo -e "${INFO} ${GreenBG} 客户端规则: ${v2ray_client_config_yaml_ruleset} ${Font}"
    echo -e "${INFO} ${GreenBG} 服务端配置: ${v2ray_conf} ${Font}"
    echo -e "${INFO} ${GreenBG} nginx配置: ${nginx_conf} ${Font}"
}

restart_firewall() {
    if [[ $(which firewalld) ]]; then
        systemctl enable firewalld
        systemctl start firewalld
        echo -e "${OK} ${GreenBG} firewalld 已开启 ${Font}"
    fi

    if [[ $(which ufw) ]]; then
        systemctl enable ufw
        systemctl start ufw
        echo -e "${OK} ${GreenBG} ufw 已开启 ${Font}"
    fi
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${OK} ${GreenBG} 存在新版本，是否更新 [Y/N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            wget -N --no-check-certificate "https://raw.githubusercontent.com/taurusni/V2ray_tls_ws/${github_branch}/install.sh"
            echo -e "${OK} ${GreenBG} 更新完成 ${Font}"
            exit 0
            ;;
        *) ;;

        esac
    else
        echo -e "${OK} ${GreenBG} 当前版本为最新版本 ${Font}"
    fi
}

maintain() {
    echo -e "${RedBG}该选项暂时无法使用${Font}"
    echo -e "${RedBG}$1${Font}"
    exit 0
}

modify_camouflage_path() {
    [[ -z ${camouflage_path} ]] && camouflage_path=1
    sed -i "/location/c \\\tlocation \/${camouflage_path}\/" ${nginx_conf}          # Modify the camouflage path of the nginx configuration file
    sed -i "/\"path\"/c \\\t  \"path\": \"\/${camouflage_path}\/\"" ${v2ray_conf}   # Modify the camouflage path of the v2ray server configuration file
    sed -i "99c \"path\": \"${camouflage}\"," "${v2ray_client_config_json}"         # Modify the camouflage path of the v2ray client configuration file
    sed -i "60c \ \ \ \ path: ${camouflage}" "${v2ray_client_config_yaml}"          # Modify the camouflage path of the v2ray client configuration file
    judge "V2ray camouflage path modified"
}

menu() {
    echo -e "\t V2ray 安装管理脚本 ${Red}[${shell_version}]${Font}"
    echo -e "\t---authored by taurus---"
    echo -e "\thttps://github.com/taurusni/V2ray_tls_ws\n"
    echo -e "当前已安装版本:${shell_mode}\n"

    echo -e "—————————————— 安装向导 ——————————————"""
    echo -e "${Green}0.${Font}  升级 脚本"
    echo -e "${Green}1.${Font}  安装 V2Ray (Nginx+ws+tls)"
    echo -e "${Green}2.${Font}  升级 V2Ray core"
    echo -e "—————————————— 配置变更 ——————————————"
    echo -e "${Green}3.${Font}  变更 UUID"
    echo -e "${Green}4.${Font}  变更 alterid"
    echo -e "${Green}5.${Font}  变更 port"
    echo -e "${Green}6.${Font}  变更 TLS 版本(仅ws+tls有效)"
    echo -e "${Green}7.${Font}  变更 伪装路径"
    echo -e "—————————————— 查看信息 ——————————————"
    echo -e "${Green}8.${Font}  查看 实时访问日志"
    echo -e "${Green}9.${Font}  查看 实时错误日志"
    echo -e "${Green}10.${Font} 查看 V2Ray客户端配置信息"
    echo -e "—————————————— 其他选项 ——————————————"
    echo -e "${Green}11.${Font} 安装 bbr"
    echo -e "${Green}12.${Font} 安装 MTproxy(支持TLS混淆)"
    echo -e "${Green}13.${Font} 证书 有效期更新"
    echo -e "${Green}14.${Font} 卸载 V2Ray"
    echo -e "${Green}15.${Font} 更新 证书crontab计划任务"
    echo -e "${Green}16.${Font} 清空 证书遗留文件"
    echo -e "${Green}17.${Font} 更新 V2ray Dat"
    echo -e "${Green}18.${Font} 退出 \n"

    read -rp "请输入数字：" menu_num
    case $menu_num in
    0)
        update_sh
        ;;
    1)
        shell_mode="ws"
        install_v2ray_ws_tls
        ;;
    2)
        bash <(curl -L -s https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
        ;;
    3)
        read -rp "请输入UUID:" UUID
        modify_UUID
        start_process_systemd
        ;;
    4)
        read -rp "请输入alterID:" alterID
        modify_alterid
        start_process_systemd
        ;;
    5)
        read -rp "请输入连接端口:" port
        if grep -q "ws" $v2ray_client_config_json; then
            modify_nginx_port
        fi
        start_process_systemd
        ;;
    6)
        tls_type
        ;;
    7)
        read -rp "请输入伪装路径(注意！不需要加斜杠 eg:ray):" camouflage_path
        modify_camouflage_path
        start_process_systemd
        ;;
    8)
        show_access_log
        ;;
    9)
        show_error_log
        ;;
    10)
        notify_users
        ;;
    11)
        read -rp "安转默认bbr还是增强版(增强版可能有兼容性问题) - 默认Y" bbr_version
        [[ -z ${bbr_version} ]] && bbr_version="Y"
        case $bbr_version in
            [yY][eE][sS] | [yY])
                bbr_boost_sh
            ;;
        *)
            bbr_boost_sh_2
            ;;
        esac
        ;;
    12)
        mtproxy_sh
        ;;
    13)
        stop_process_systemd
        ssl_update_manuel
        start_process_systemd
        ;;
    14)
        source '/etc/os-release'
        uninstall_all
        ;;
    15)
        acme_cron_update
        ;;
    16)
        delete_tls_key_and_crt
        ;;
    17)
        v2ray_update_dat
        start_process_systemd
        ;;
    18)
        exit 0
        ;;
    *)
        echo -e "${RedBG}请输入正确的数字${Font}"
        ;;
    esac
}

judge_mode() {
    if [[ -f "${v2ray_bin_dir}/v2ray" ]]; then
        if grep -q "\"network\": \"ws\"" "${v2ray_client_config_json}"; then
            shell_mode="ws"
        fi
    fi
}

main() {
    judge_mode
    menu
}

main
