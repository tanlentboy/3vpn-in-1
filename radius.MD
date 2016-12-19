#!/bin/sh
clear                                                                                           
echo ""
echo -e "\033[7m"
echo "+---------------------------------------------------------------------+"    
echo "+                                                                     +"    
echo "+          PPTP/L2TP/OPENVPN + [Optional: Freeradius + Mysql]         +"    
echo "+                                                                     +"    
echo "+           Daloradius or RadiusManager  [Optional: apache]           +"    
echo "+                                                                     +"    
echo "+          Power by: www.yishanhome.com (yishanhome@gmail.com)        +"    
echo "+                                                                     +"    
echo "+                  Platform: CentOS 6.0 and 5.x                       +"    
echo "+                                                                     +"    
echo "+---------------------------------------------------------------------+"    
echo -e "\033[0m"
echo
# "=========================================================================="
#Disable SeLinux
if [ -s /etc/selinux/config ]; then
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
fi
platform=`uname -i`
if [ $platform = "x86_64" ]; then
  sysinfo="x86-64"
  else
   sysinfo="x86"  
fi
if [ $platform = "unknown" ]; then
  platform="i386"
fi

# "=========================================================================="
# set clients ip address
# pptp, local_ip is the server ip, remote_id is the range of client
p_local="10.10.77.0"
p_local_ip="10.10.77.1"
p_remote_ip="10.10.77.100-200"

#openvpn, local_ip is the client ip subnet
o_local_ip="10.10.88.0"

# l2tp, local_ip is the server ip, remote_id is the range of client
l_local="10.10.99.0"
l_local_ip="10.10.99.1"
l_remote_ip="10.10.99.100-10.10.99.200"

# parameters
wd=`pwd`
wd_work=`pwd`/work
mkdir -p $wd_work
server_ip=`ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk 'NR==1 { print $1}'`
radius_server="127.0.0.1"
mysql_root_pwd="yishanhome.com"
secret_key="yishanhome.com"
radusr="root"
radhost="localhost"
myusr_rad="radius"
mypsw_radius="radius123"
myusr_cts="conntrack"
mypsw_cts="conn123"
radius_dir="/usr/local/etc/raddb"
etc_dir="/usr/local/etc"
sbin_dir="/usr/sbin"
if [ "$1" != "" ]; then
down_url=$1
else
down_url="http://china123.10dig.net"
fi

# "=========================================================================="
get_char()
{
  SAVEDSTTY=`stty -g`
  stty -echo
  stty cbreak
  dd if=/dev/tty bs=1 count=1 2> /dev/null
  stty -raw
  stty echo
  stty $SAVEDSTTY
}

init()
{
  echo ""
  echo "Please input server ip:"
  read -p "(Default ip: $server_ip):" temp
  if [ "$temp" != "" ]; then
    server_ip=$temp
  fi
  echo ""
  echo "Please input the freeradius service IP:"
  read -p "(Default IP: $radius_server):" temp
  if [ "$temp" != "" ]; then
    radius_server=$temp
  fi
  echo ""
  echo "Please input the freeradius secret key:"
  read -p "(Default secret key: $secret_key):" temp
  if [ "$temp" != "" ]; then
    secret_key=$temp
  fi
if [ $option_a = "1" ]; then
www_path="/var/www/html/yishan"
httpusr="apache"
  else
www_path="/home/wwwroot/yishan" 
httpusr="www"
fi
if [ $option_a != "0" ]; then
  echo ""
  echo "Please input radiusmanager or daloradius wwwsite dir:"
  read -p "(Default wwwsite dir: $www_path):" temp
  if [ "$temp" != "" ]; then
    www_path=$temp
  fi
mkdir -p $www_path
fi
if [ $radius_server = "127.0.0.1" ]; then
testmysql=`rpm -qa|grep mysql-server|wc -l`
testmysql1=`service mysql start|wc -l`
mysqlpwd()
{
  echo ""
  read -p "Please input the root password of Mysql:" temp
  if [ "$temp" != "" ]; then
 if [ $testmysql = "0" ] && [ $testmysql1 = "0" ]; then
echo "install mysql"
mysql_root_pwd=$temp
 else
cat >>test.sql<<END
quit
END
  mysql -uroot -p$temp<test.sql
     stat=$?
        if [ $stat -eq 0 ]; then
                echo "test database and initialize database success!";
                rm -rf test.sql
                mysql_root_pwd=$temp
        else
mysqlpwd
        fi   
        fi

    else 
   mysqlpwd
  fi 
 }
mysqlpwd
fi 
  echo ""
  echo -e "\033[5mPress any key to continue...\033[0m"
  get_char
  clear
}
# "=========================================================================="
install_mysql()
{
  echo "+--------------------------------------+"
  echo "+          install mysql               +"
  echo "+--------------------------------------+"

 if [ $testmysql = "0" ] && [ $testmysql1 = "0" ]; then
    cd $wd_work
tar -zxvf mysql-5.1.56.tar.gz
cd mysql-5.1.56/
./configure --prefix=/usr/local/mysql \
--with-unix-socket-path=/var/lib/mysql/mysql.sock \
--with-extra-charsets=all \
--enable-thread-safe-client \
--enable-assembler \
--with-charset=utf8 \
--enable-thread-safe-client \
--with-extra-charsets=all \
--with-big-tables \
--with-readline \
--with-ssl \
--with-embedded-server \
--enable-local-infile
make && make install
cd ../

groupadd mysql
useradd -s /sbin/nologin -M -g mysql mysql

mv /etc/my.cnf /etc/my.cnf.bak
cp /usr/local/mysql/share/mysql/my-medium.cnf /etc/my.cnf
sed -i 's/skip-locking/skip-external-locking/g' /etc/my.cnf
/usr/local/mysql/bin/mysql_install_db --user=mysql
chown -R mysql /usr/local/mysql/var
chgrp -R mysql /usr/local/mysql/.
cp /usr/local/mysql/share/mysql/mysql.server /etc/init.d/mysql
chmod 755 /etc/init.d/mysql

cat > /etc/ld.so.conf.d/mysql.conf<<EOF
/usr/local/mysql/lib/mysql
/usr/local/lib
EOF
ldconfig

ln -s /usr/local/mysql/lib/mysql /usr/lib/mysql
ln -s /usr/local/mysql/include/mysql /usr/include/mysql
/etc/init.d/mysql start
ln -s /usr/local/mysql/bin/mysql /usr/bin/mysql
ln -s /usr/local/mysql/bin/mysqldump /usr/bin/mysqldump
ln -s /usr/local/mysql/bin/myisamchk /usr/bin/myisamchk
/usr/local/mysql/bin/mysqladmin -u root password $mysql_root_pwd
/etc/init.d/mysql restart
  fi
chkconfig mysql on

#if [ -e /tmp/mysql.sock ]; then
#mkdir -p /var/lib/mysql/
#ln -s /tmp/mysql.sock /var/lib/mysql/mysql.sock
#fi
}
# "=========================================================================="
install_apache()
{
  echo "+--------------------------------------+"
  echo "+        install apache  + PHP         +"
  echo "+--------------------------------------+"
cd $wd_work
yum install -y httpd mod_ssl php php-common php-gd php-pear php-pecl-memcache php-mhash php-xml
yum install -y mysql-devel curl php-mysql php-mcrypt compat-libstdc++-33 libtool-ltdl-devel
chkconfig httpd on
service httpd start
php_version=`php -r 'echo PHP_VERSION;'`
php_version=${php_version:0:3}

tar zxvf ioncube_loaders_lin_$sysinfo.tar.gz
cp -rf ioncube /usr/local/
cat >>/etc/php.ini << END
zend_extension=/usr/local/ioncube/ioncube_loader_lin_$php_version.so
END
service httpd restart
}

# "=========================================================================="
install_freeradius()
{
  echo "+--------------------------------------+"
  echo "+         install freeradius           +"
  echo "+--------------------------------------+"
 yum remove -y freeradius2 freeradius2-mysql freeradius2-krb5 freeradius2-utils freeradius2-python
 service radiusd stop
if [ -e $radius_dir ]; then
 mv $radius_dir $radius_dir."bak"
fi
cd $wd_work
if [ $option_b = "1" ]; then 
tar xvf freeradius-server-2.1.10.tar.gz
cd freeradius-server-2.1.10
fi
if [ $option_b = "2" ]; then 
tar xvf freeradius-server-2.1.8-dmamod-1.tar.gz
cd freeradius-server-2.1.8
fi
./configure
make
make install
cat >>/etc/ld.so.conf<< END
/usr/local/lib
END
/sbin/ldconfig
radiusd -X&
sleep 60
chmod 755 $wd_work/radiusd
cp -f $wd_work/radiusd /etc/init.d
    chkconfig radiusd on
}
# "=========================================================================="
install_radiusmanager()
{
  echo "+--------------------------------------+"
  echo "+        install radiusmanager         +"
  echo "+--------------------------------------+"
cd $wd_work
chmod 644 $radius_dir/dictionary
chown $httpusr $radius_dir
chown $httpusr $radius_dir/clients.conf

cat >>/etc/rc.d/rc.sysinit<<END
/sbin/ifconfig eth0 down
/sbin/ifconfig eth0 hw ether 00:D0:09:B8:B7:34
/sbin/ifconfig eth0 up
END

tar zxvf radiusmanager-3.9.0-lnmp.tar.gz
cd radiusmanager-3.9.0/
cp -r www/radiusmanager/* $www_path
chown $httpusr $www_path/config/system_cfg.php
chown $httpusr $www_path/config/paypal_cfg.php
chown $httpusr $www_path/config/netcash_cfg.php
chown $httpusr $www_path/config/authorizenet_cfg.php
chown $httpusr $www_path/config/dps_cfg.php
chown $httpusr $www_path/config/2co_cfg.php
chmod 600 $www_path/config/system_cfg.php
chmod 600 $www_path/config/paypal_cfg.php
chmod 600 $www_path/config/netcash_cfg.php
chmod 600 $www_path/config/authorizenet_cfg.php
chmod 600 $www_path/config/dps_cfg.php
chmod 600 $www_path/config/2co_cfg.php
cp bin/rm* /usr/local/bin
cp bin/rootexec /usr/local/sbin
chmod 4755 /usr/local/sbin/rootexec
cp etc/radiusmanager.cfg /etc
chown $radusr /etc/radiusmanager.cfg
chmod 600 /etc/radiusmanager.cfg
mysqldump -h $radhost -u $myusr_rad -p$mypsw_radius radius > radius_backup.sql
sed -i -e "s/testing123/$secret_key/g" sql/radius.sql
sed -i -e "s/192.168.0.8/$server_ip/g" sql/radius.sql
cat >> mysql-temp.sql << END
DROP DATABASE radius;
DROP DATABASE conntrack;
CREATE DATABASE radius;
CREATE DATABASE conntrack;
CREATE USER '$myusr_rad'@'$radhost' IDENTIFIED BY '$mypsw_radius';
CREATE USER '$myusr_cts'@'$radhost' IDENTIFIED BY '$mypsw_cts';
GRANT ALL ON $myusr_rad.* TO $myusr_rad@$radhost;
GRANT ALL ON $myusr_cts.* TO $myusr_cts@$radhost;
END
mysql -u root -f -p$mysql_root_pwd< mysql-temp.sql
mysql -h $radhost -u $myusr_rad -p$mypsw_radius radius < sql/radius.sql
mysql -h $radhost -u $myusr_cts -p$mypsw_cts conntrack < sql/conntrack.sql
cp rc.d/rmpoller /etc/init.d
chown root.root /etc/init.d/rmpoller
chmod 755 /etc/init.d/rmpoller
cp rc.d/rmconntrack /etc/init.d
chown root.root /etc/init.d/rmconntrack
chmod 755 /etc/init.d/rmconntrack
cp etc/logrotate.d/radiusd /etc/logrotate.d/radiusd
chown $httpusr $radius_dir
#chmod 755 rc.d/redhat/radiusd
#cp rc.d/redhat/radiusd /etc/init.d
if [ -e /tmp/mysql.sock ]; then
sed -i -e "s/var\/lib\/mysql\/mysql.sock/tmp\/mysql.sock/" /etc/radiusmanager.cfg
fi
sed -i -e "s@/var/www/html/radiusmanager@$www_path@g" /etc/radiusmanager.cfg
sed -i -e "s@/var/www/html/radiusmanager@$www_path@g" $www_path/config/system_cfg.php
mv $radius_dir/clients.conf $radius_dir/clients.conf.bak
cat >>$radius_dir/clients.conf<<END
client $server_ip {
	secret		= $secret_key
	shortname	= $server_ip
}
client 127.0.0.1 {
	secret		= $secret_key
	shortname	= Localhost
}
END
chown $httpusr $radius_dir/clients.conf
service radiusd restart
}
# "=========================================================================="
install_daloradius()
{
  echo "+--------------------------------------+"
  echo "+         install daloradius           +"
  echo "+--------------------------------------+"
cd $wd_work
yum -y install php-pear-DB
echo "include_path=\".:/usr/share/pear:/usr/share/php\"" >>/usr/local/php/etc/php.ini
/usr/local/php/sbin/php-fpm restart

tar -zxvf daloradius-0.9-8.tar.gz
mysqldump -h $radhost -u $myusr_rad -p$mypsw_radius radius > radius_backup.sql
cat >> mysql-temp.sql << END
DROP DATABASE radius;
CREATE DATABASE radius;
CREATE USER '$myusr_rad'@'$radhost' IDENTIFIED BY '$mypsw_radius';
GRANT ALL ON $myusr_rad.* TO $myusr_rad@$radhost;
END
mysql -u root -f -p$mysql_root_pwd< mysql-temp.sql
    sed -i -e "s/testing123/$secret_key/g" $radius_dir/clients.conf
    sed -i -e "s/radius/$myusr_rad/" $radius_dir/sql/mysql/admin.sql
    sed -i -e "s/radpass/$mypsw_radius/" $radius_dir/sql/mysql/admin.sql
    sed -i -e "s/localhost/127.0.0.1/" $radius_dir/sql/mysql/admin.sql
    sed -i -e "s/radpass/$mypsw_radius/" $radius_dir/sql.conf
    sed -i -e 's/server = "localhost"/server = "127.0.0.1"/' $radius_dir/sql.conf
    sed -i -e 's/^#[ \t]$INCLUDE *sql.conf$/$INCLUDE sql.conf/' $radius_dir/radiusd.conf
    sed -i -e 's/^#[ \t]*sql$/sql/' $radius_dir/sites-available/default
service mysql start
    mysql --user=root --password=$mysql_root_pwd < $radius_dir/sql/mysql/admin.sql
    mysql --user=root --password=$mysql_root_pwd radius < $radius_dir/sql/mysql/schema.sql
    mysql --user=root --password=$mysql_root_pwd radius < $radius_dir/sql/mysql/ippool.sql
    mysql --user=root --password=$mysql_root_pwd radius < $radius_dir/sql/mysql/nas.sql
    mysql --user=root --password=$mysql_root_pwd radius < $radius_dir/sql/mysql/cui.sql
    mysql --user=root --password=$mysql_root_pwd radius < $radius_dir/sql/mysql/wimax.sql

cat > $wd_work/w.sql <<EOF
INSERT INTO radcheck (id, username, attribute, op, value) VALUES (1, 'user', 'Cleartext-Password', ':=', 'yishanhome.com');
EOF
mysql --user=root --password=$mysql_root_pwd radius < $wd_work/w.sql
sed -i -e "s/'administrator','radius'/'admin','yishanhome.com'/" daloradius-0.9-8/contrib/db/mysql-daloradius.sql
mysql -u root -p$mysql_root_pwd radius < daloradius-0.9-8/contrib/db/mysql-daloradius.sql
echo "delete from radius.operators where username='liran';" | mysql -u root -p$mysql_root_pwd radius
sed -i -e "s/'1'/'2'/" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/\['CONFIG_DB_HOST'\] = '127.0.0.1'/\['CONFIG_DB_HOST'\] = '$radhost'/" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/\['CONFIG_DB_USER'\] = 'root'/\['CONFIG_DB_USER'\] = '$myusr_rad'/" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/\['CONFIG_DB_PASS'\] = ''/\['CONFIG_DB_PASS'\] = '$mypsw_radius'/g" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/testing123/$secret_key/" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/'usergroup'/'radusergroup'/" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/'en'/'ch'/" daloradius-0.9-8/library/daloradius.conf.php
sed -i -e "s/freeradius/radius/" daloradius-0.9-8/library/exten-radius_log.php

tar -zxvf daloradius-0.9-8-hh.tar.gz -C daloradius-0.9-8/
cp -r daloradius-0.9-8/* $www_path
service radiusd restart
}
# "=========================================================================="
install_pptp()
{
  echo "+--------------------------------------+"
  echo "+          install pptp                +"
  echo "+--------------------------------------+"
  ret=`rpm -qa|grep pptpd|wc -l`
  if [ $ret = "0" ]; then
    cd $wd_work
    yum install -y ppp
if [[ `head -n 1 /etc/issue` =~ "6." ]]; then
sysver="2.el6"
fi
if [[ `head -n 1 /etc/issue` =~ "5." ]]; then
sysver="1.rhel5.1"
fi
    rpm -ivh $wd_work/pptpd-1.3.4-$sysver.$platform.rpm
    sed -i -e 's/logwtmp/#logwtmp/' /etc/pptpd.conf
  
cat >>/etc/pptpd.conf<<EOF
localip $p_local_ip
remoteip $p_remote_ip
EOF
  
    echo "+--------------------------------------+"
    echo "+    install radiusclient for pptp     +"
    echo "+--------------------------------------+"
    
    etc_dir_t=$(echo "$etc_dir" | sed 's/\//\\\//g')
    sbin_dir_t=$(echo "$sbin_dir" | sed 's/\//\\\//g')
    cp -R $wd_work/radiusclient $etc_dir/radiusclient
    cp -f $etc_dir/radiusclient/radiusclient.conf.in $etc_dir/radiusclient/radiusclient.conf
    sed -i -e "s/@etcdir@/$etc_dir_t/" $etc_dir/radiusclient/radiusclient.conf
    sed -i -e "s/@etcdir@/$etc_dir_t/" $etc_dir/radiusclient/dictionary
    sed -i -e "s/@sbindir@/$sbin_dir_t/" $etc_dir/radiusclient/radiusclient.conf
  
cat >> $etc_dir/radiusclient/servers<<EOF
$radius_server $secret_key
EOF

    sed -i -e 's/^#ms-dns 10.0.0.1$/ms-dns 8.8.8.8/' /etc/ppp/options.pptpd
    sed -i -e 's/^#ms-dns 10.0.0.2$/ms-dns 8.8.4.4/' /etc/ppp/options.pptpd
    radius_so=`find /usr -name radius.so`
  
cat >> /etc/ppp/options.pptpd <<EOF
plugin $radius_so
radius-config-file $etc_dir/radiusclient/radiusclient.conf
EOF

cat >> /etc/hosts <<END
127.0.0.1 `hostname`
END
    chkconfig pptpd on
    service pptpd restart
  fi
}
# "=========================================================================="
install_openvpn()
{
  echo "+--------------------------------------+"
  echo "+          install openvpn             +"
  echo "+--------------------------------------+"
  ret=`rpm -qa|grep openvpn|wc -l`
  if [ $ret = "0" ]; then
    cd $wd_work
    yum install -y openvpn
    
    key_path=/etc/openvpn
    key_path=$(echo "$key_path" | sed 's/\//\\\//g')
    mkdir $wd/openvpn
    cp -R /usr/share/openvpn/easy-rsa/2.0 $wd/openvpn/easy-rsa
    cp -f $wd_work/openvpn-server.conf /etc/openvpn/server.conf
    sed -i -e "s/key_path/$key_path/g" /etc/openvpn/server.conf
    sed -i -e "s/@server_ip@/$o_local_ip/g" /etc/openvpn/server.conf
    cp -f $wd_work/vars $wd/openvpn/easy-rsa
    cd $wd/openvpn/easy-rsa
    . ./vars
    ./clean-all --batch
    ./build-ca --batch
    ./build-key-server --batch server
    ./build-dh --batch
    
    cp -f keys/*.crt /etc/openvpn/
    cp -f keys/server.key /etc/openvpn/
    cp -f keys/dh1024.pem /etc/openvpn/
    
    cd $wd/openvpn
    mkdir client
    cd $wd
    cp -f $wd_work/openvpn-client.ovpn $wd/openvpn/client/client.ovpn
    sed -i -e "s/server_ip/$server_ip/g" $wd/openvpn/client/client.ovpn
    cp -f $wd/openvpn/easy-rsa/keys/ca.crt $wd/openvpn/client/
    
    echo "+--------------------------------------+"
    echo "+   install radiusplugin for openvpn   +"
    echo "+--------------------------------------+"
    cd $wd_work

    tar xf radiusplugin_v2.1_beta9.tar.gz
    cd radiusplugin
    make
    cp radiusplugin.so /etc/openvpn/
    sed -i -e "s/sharedsecret=testpw/sharedsecret=$secret_key/" radiusplugin.cnf
    cp radiusplugin.cnf /etc/openvpn/
    
    chkconfig openvpn on
    service openvpn restart
  fi
}
# "=========================================================================="
install_l2tp()
{
  echo "+--------------------------------------+"
  echo "+          install openswan            +"
  echo "+--------------------------------------+"
  ret=`rpm -qa|grep openswan|wc -l`
  if [ $ret = "0" ]; then
    cd $wd_work

    rpm -ivh openswan-2.6.24rc5-1.$platform.rpm 
    cp -f $wd_work/l2tp.conf /etc/ipsec.d/l2tp.conf
    cp -f $wd_work/no_oe.conf /etc/ipsec.d/no_oe.conf
    sed -i -e "s/@server_ip@/$server_ip/g" /etc/ipsec.d/l2tp.conf
    sed -i -e "s/oe=off/#oe=off/g" /etc/ipsec.conf
    sed -i -e "s/virtual_private=/virtual_private=%v4:10.0.0.0\/8,%v4:192.168.0.0\/16,%v4:172.16.0.0\/12/g" /etc/ipsec.conf
cat >> /etc/ipsec.conf <<EOF
include /etc/ipsec.d/l2tp.conf
include /etc/ipsec.d/no_oe.conf
EOF

cat >> /etc/ipsec.secrets <<EOF
$server_ip  %any:  PSK  "$secret_key"
EOF

    chkconfig ipsec on
    service ipsec restart
    ipsec verify
    
    echo "+--------------------------------------+"
    echo "+          install xl2tp               +"
    echo "+--------------------------------------+"
cd $wd_work
yum install -y xl2tpd
mv /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.ori 
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
listen-addr = $server_ip
ipsec saref = yes

[lns default]
ip range = $l_remote_ip
local ip = $l_local_ip
refuse chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOF

    radius_so=`find /usr -name radius.so`
  
cat >> /etc/ppp/options.xl2tpd <<EOF
plugin $radius_so
radius-config-file $etc_dir/radiusclient/radiusclient.conf
EOF


    chkconfig xl2tpd on
    service xl2tpd restart
  fi
}
# "=========================================================================="
set_iptables()
{
  echo "+--------------------------------------+"
  echo "+          iptables setting            +"
  echo "+--------------------------------------+"
cd $wd_work
  yum install -y iptables
  sed -i "s/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g" /etc/sysctl.conf

cat >> /etc/sysctl.conf <<EOF
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

  sysctl -p
  
  iptables -A INPUT -i tun+ -j ACCEPT
  iptables -A FORWARD -i tun+ -j ACCEPT
  iptables -A INPUT -i tap+ -j ACCEPT
  iptables -A FORWARD -i tap+ -j ACCEPT
  iptables -A INPUT -p udp -d $server_ip --dport 500 -j ACCEPT
  iptables -A INPUT -p udp -d $server_ip --dport 4500 -j ACCEPT
  iptables -A INPUT -p udp -d $server_ip --dport 1701 -j ACCEPT
  iptables -t nat -A POSTROUTING -s $p_local/24 -j MASQUERADE -o eth0
  iptables -t nat -A POSTROUTING -s $o_local_ip/24 -j MASQUERADE -o eth0
  iptables -t nat -A POSTROUTING -s $l_local/24 -j MASQUERADE -o eth0
  iptables -t nat -A POSTROUTING -s $p_local/24 -j SNAT --to-source $server_ip
  iptables -t nat -A POSTROUTING -s $o_local_ip/24 -j SNAT --to-source $server_ip
  iptables -t nat -A POSTROUTING -s $l_local/24 -j SNAT --to-source $server_ip
  iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 8.8.8.8
  iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 8.8.4.4
  
  service iptables save

  for each in /proc/sys/net/ipv4/conf/*
  do
    echo 0 > $each/accept_redirects
    echo 0 > $each/send_redirects
  done
  service iptables restart
}
# "=========================================================================="
check_status()
{
  if [ $# -eq 1 ]; then
    ret=`ps -ef|grep $1|grep -v grep|wc -l`
    if [ $ret = "0" ]; then
      echo -e "$1\t\t\t[\033[31;5;1m Failed \033[0m]"
    else
      echo -e "$1\t\t\t[\033[1m OK \033[0m]"
    fi
  fi
  
  if [ $# -eq 2 ]; then
    ret=`ps -ef|grep $1|grep $2|grep -v grep|wc -l`
    if [ $ret = "0" ]; then
      echo -e "$1($2)\t\t\t[\033[31;5;1m Failed \033[0m]"
    else
      echo -e "$1($2)\t\t\t[\033[1m OK \033[0m]"
    fi
  fi
}
# "=========================================================================="
usage()
{
  option="4"
  echo "Now you can install vpn software as below:"
  echo "0. Not install vpn software"
  echo "1. pptp"
  echo "2. openvpn"
  echo "3. pptp+l2tp"
  echo "4. all"
  echo ""
  echo "Please input your option:"
  read -p "(Default option: $option):" temp
  if [ "$temp" != "" ]; then
    option=$temp
  fi
  echo ""
  echo ""
  option_a="0"
  echo "Now you can install web services software as below:"
  echo "0. Not install Web services "
  echo "1. apache + PHP "
  echo ""
  echo "Please input your option:"
  read -p "(Default option: $option_a):" temp
  if [ "$temp" != "" ]; then
    option_a=$temp
  fi  
  echo ""
  echo ""
  option_b="0"
  echo "Now you can install web manager software as below:"
  echo "0. Not install Web Manager "
  echo "1. daloradius "
  echo "2. radiusmanager "
  echo ""
  echo "Please input your option:"
  read -p "(Default option: $option_b):" temp
  if [ "$temp" != "" ]; then
    option_b=$temp
  fi
}
# "=========================================================================="
# root privilege is mandatory
if [ $(id -u) -ne 0 ]; then
  echo "Error: You must get root privilege at first."
  exit 1
fi

option=$1

if [ $# -ne 1 ]; then
	usage
fi

while [ $option != "1" -a $option != "2" -a $option != "3" -a $option != "4" ]
do
  usage
done
init
check_source()
{
  echo "checking $1"
  if [ -e $1 ]; then
    echo "OK!"
  else
    echo "Error: $1 not found!!!download now......"
    wget -c $down_url/$1
    check_source $1
  fi
}
# "=========================================================================="
echo "+--------------------------------------+"
echo "+    Update source list and init       +"
echo "+--------------------------------------+"
# set the source url
echo "============================check files=================================="
cd $wd_work
check_source openswan-2.6.24rc5-1.$platform.rpm
check_source mysql-5.1.56.tar.gz
check_source ioncube_loaders_lin_$sysinfo.tar.gz
check_source freeradius-server-2.1.8-dmamod-1.tar.gz
check_source freeradius-server-2.1.10.tar.gz
check_source radiusmanager-3.9.0-lnmp.tar.gz
check_source daloradius-0.9-8.tar.gz
check_source daloradius-0.9-8-hh.tar.gz
check_source pptpd-1.3.4-2.el6.$platform.rpm
check_source pptpd-1.3.4-1.rhel5.1.$platform.rpm
check_source radiusplugin_v2.1_beta9.tar.gz
check_source install.tar.gz
echo "============================check files=================================="
if [[ `head -n 1 /etc/issue` =~ "6." ]]; then
rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/$platform/epel-release-6-7.noarch.rpm
fi
if [[ `head -n 1 /etc/issue` =~ "5." ]]; then
rpm -Uvh http://dl.fedoraproject.org/pub/epel/5/$platform/epel-release-5-4.noarch.rpm
fi
rpm -Uvh http://repo.webtatic.com/yum/centos/5/$platform/webtatic-release-5-1.noarch.rpm
yum install -y update
yum install -y gcc gcc-c++ rpm-build vim-enhanced lsof make crypt* libgcrypt*
yum -y install gcc-g77 flex bison file libtool libtool-libs autoconf kernel-devel
yum -y install libjpeg libjpeg-devel libpng libpng-devel libpng10 libpng10-devel gd gd-devel freetype
yum -y install freetype-devel libxml2 libxml2-devel zlib zlib-devel glib2 glib2-devel bzip2 bzip2-devel
yum -y install libevent libevent-devel ncurses ncurses-devel curl curl-devel e2fsprogs e2fsprogs-devel
yum -y install krb5 krb5-devel libidn libidn-devel openssl openssl-devel vim-minimal nano fonts-chinese
yum -y install gettext gettext-devel ncurses-devel gmp-devel pspell-devel unzip

cp /usr/bin/vim /usr/bin/vi
echo "set nu" >> /etc/vimrc

cd $wd_work
tar xf install.tar.gz

if [ $radius_server = "127.0.0.1" ]; then
if [ $option_a = "1" ]; then 
  install_apache
fi
install_mysql
if [ $option_b = "1" ]; then 
  install_freeradius
  install_daloradius
  rampath=$(echo $www_path | awk -F\/ '{print $NF}')
fi
if [ $option_b = "2" ]; then 
  install_freeradius
  install_radiusmanager
  rampath="$(echo $www_path | awk -F\/ '{print $NF}')/admin.php"
fi
  check_status mysql
  check_status freeradius
fi
  set_iptables


if [ $option = "1" ]; then
  install_pptp
  check_status pptpd
fi

if [ $option = "2" ]; then
  install_openvpn
  check_status openvpn
fi

if [ $option = "3" ]; then
  install_pptp
  install_l2tp
  check_status pptpd
  check_status ipsec
  check_status xl2tpd
fi

if [ $option = "4" ]; then
  install_openvpn
  install_pptp
  install_l2tp
  check_status pptpd
  check_status openvpn
  check_status ipsec
  check_status xl2tpd
fi
# "=========================================================================="
if [ $radius_server != "127.0.0.1" ]; then
sed -i -e "s/name=127.0.0.1/name=$radius_server/" /etc/openvpn/radiusplugin.cnf
sed -i -e "s/sharedsecret=testpw/sharedsecret=$secret_key/" /etc/openvpn/radiusplugin.cnf
sed -i -e "s/localhost:1812/$radius_server:1812/" $etc_dir/radiusclient/radiusclient.conf
sed -i -e "s/localhost:1813/$radius_server:1813/" $etc_dir/radiusclient/radiusclient.conf
mv -f $etc_dir/radiusclient/servers $etc_dir/radiusclient/servers.bak
cat >> $etc_dir/radiusclient/servers <<EOF
$radius_server $secret_key
EOF
printf "
#Please in your freeradius server execute the following command
iptables -A INPUT -i eth0 -p udp -s $server_ip --dport 1812 -j ACCEPT
iptables -A INPUT -i eth0 -p udp -s $server_ip --dport 1813 -j ACCEPT
cat >> /etc/raddb/clients.conf <<EOF
client localhost {
        ipaddr = $server_ip
        secret = $secret_key
        require_message_authenticator = no
        nastype     = other
}
EOF
service radiusd restart
#Successfully installed!
"
else
if [ $option_a != "0" ]; then
echo "web manager http://$server_ip/$rampath"
echo "Manager name:admin   Password:yishanhome.com"
fi
fi
echo "VPN SERVER IP:$server_ip"
echo "test name:user   Password:yishanhome.com"
echo "You need to restart the computer!!!"