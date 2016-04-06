#!/bin/bash -x

set -e

# start sxmonitor
RUN_AS=nagios
NAGIOS_SX_CFG="/data/etc"
SSMTP_CONF="/data/ssmtp.conf"
ADMIN_KEY_PATH="/data/admin.key"
SUGGEST_CMD="docker run -p 9443:443 -v /data/sxmonitor:/data --name=sxmonitor"

for i in cert.pem key.pem; do
	if ! [ -r /data/$i ]; then
		echo $i not found. Please use the following syntax and make sure the sxmonitor user can read the file: $i
		echo Use: $SUGGEST_CMD --restart=always -d sxmonitor
		exit 1
	fi
done

# fix permissions
if ! getent passwd $RUN_AS > /dev/null 2>&1; then
	adduser $RUN_AS 
fi

echo Copying SSL certs...
mkdir -p /etc/nginx/ssl
cp /data/cert.pem /data/key.pem /etc/nginx/ssl/
chmod 600 /data/key.pem /etc/nginx/ssl/key.pem

echo Updating sxmonitor config files...

if ! [ -r "$ADMIN_KEY_PATH" ]; then
	echo Please make the admin key available at $ADMIN_KEY_PATH
	exit 1
fi
if ! [ -d "$NAGIOS_SX_CFG" ] || ! [ -r "$SSMTP_CONF" ]; then
	if [ -z "$CLUSTER_NAME" ] || [ -z "$NOTIFY_EMAIL" ] || [ -z "$SMTP_ADDRESS" ]; then
		echo Run:
		echo $SUGGEST_CMD -e CLUSTER_NAME=sx.cluster.tld -e CLUSTER_PORT=443 -e NOTIFY_EMAIL=me@foo.com -e SMTP_ADDRESS=smtp.mail.tld --restart=always -d sxmonitor
		exit 1
	else
		if [ -z "$CLUSTER_PORT" ]; then
			CLUSTER_PORT=443
		fi
		/srv/sxmonitor/generate_nagios_config.py --host-address $CLUSTER_NAME --port $CLUSTER_PORT --key-path $ADMIN_KEY_PATH --notify-address admin-ng@skylable.com $NAGIOS_SX_CFG
		cp /etc/ssmtp/ssmtp.conf $SSMTP_CONF
		sed -i 's/^mailhub=.*$/mailhub=$SMTP_ADDRESS/' $SSMTP_CONF
		# fix relative path to nagios cgi-bin
		sed -i 's#url_html_path=.*$#url_html_path=/#' $NAGIOS_SX_CFG/cgi.cfg
	fi
fi


# copy nagios and ssmtp cfg to live system
cp -a $NAGIOS_SX_CFG/. /etc/nagios/.
cp -f $SSMTP_CONF /etc/ssmtp/ssmtp.conf


mkdir -p /data/logs
mkdir -p /data/logs/supervisor
chown -R $RUN_AS /data /etc/nagios /srv /var/lib/php/session /var/log/php-fpm
chown $RUN_AS /usr/share/nagios/html/includes/../config.inc.php
#tail -n 0 -f /data/logs/*.log &
chmod -R go-rwx /data

if ! [ -r "/data/htpasswd" ]; then
	# no nagiosadmin account
	echo Create an account with:
	echo "$SUGGEST_CMD -ti --rm sxmonitor /usr/bin/htpasswd -c /data/htpasswd nagiosadmin"
	exit 1
else
	cp -f /data/htpasswd /etc/nginx/htpasswd
fi

/usr/bin/supervisord -c /etc/supervisor/supervisord.conf

