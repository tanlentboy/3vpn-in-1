修改VPN服务器radius认证为远程服务器
修改参数在VPN服务器运行下面脚本

radius_server="radius服务器IP"
secret_key="yishanhome.com"
etc_dir="/usr/local/etc"
sed -i -e "s/name=127.0.0.1/name=$radius_server/" /etc/openvpn/radiusplugin.cnf
sed -i -e "s/sharedsecret=testpw/sharedsecret=$secret_key/" /etc/openvpn/radiusplugin.cnf
sed -i -e "s/localhost:1812/$radius_server:1812/" $etc_dir/radiusclient/radiusclient.conf
sed -i -e "s/localhost:1813/$radius_server:1813/" $etc_dir/radiusclient/radiusclient.conf
mv -f $etc_dir/radiusclient/servers $etc_dir/radiusclient/servers.bak
cat >> $etc_dir/radiusclient/servers <<EOF
$radius_server $secret_key
EOF
修改参数在radius服务器运行下面脚本

client_ip="VPN服务器IP"
secret_key="yishanhome.com"
etc_dir="/usr/local/etc"
iptables -A INPUT -i eth0 -p udp -s $client_ip --dport 1812 -j ACCEPT
iptables -A INPUT -i eth0 -p udp -s $client_ip --dport 1813 -j ACCEPT
cat >> $etc_dir/raddb/clients.conf <<EOF
client localhost {
 ipaddr = $client_ip
 secret = $secret_key
 require_message_authenticator = no
 nastype  = other
}
EOF
