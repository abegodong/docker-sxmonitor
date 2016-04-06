## SX Console

sxmonitor dockerized

## Generate SSL cert and key

```bash
openssl genrsa -out ca.key 2048 
openssl req -new -key ca.key -out ca.csr
openssl x509 -req -days 3650 -in ca.csr -signkey ca.key -out ca.crt
cp ca.crt /data/sxmonitor/cert.pem
cp ca.key /data/sxmonitor/key.pem
```

## Provide an account on SX

Create a volume called 'sxmonitor'.

Create the sxmonitor user with read access to all the volumes that you want to
monitor and read+write access to the 'sxmonitor' volume.

```bash
$ sxacl useradd sxmonitor sx://admin@clustername
$ sxvol create -r 3 -s 1G -o sxmonitor sx://admin@clustername/sxmonitor
$ sxacl volperm --grant=read sx://admin@clustername/vol1
$ sxacl volperm --grant=read sx://admin@clustername/vol2
...
$ sxacl volperm --grant=read sx://admin@clustername/volN
```

Obtain the key for this user:

```bash
$ sxacl usergetkey sxmonitor sx://admin@clustername
```

Store the key into /data/sxmonitor/admin.key

## Start and configure your container

By default nagios listens on port 443. Use the -p option to map it to a port on the Docker host.

```bash
docker run -v /data/sxmonitor:/data \
	-p 9443:443 \
	--name=sxmonitor \
	--restart=always -d \
	-e CLUSTER_NAME=clustername -e CLUSTER_PORT=443 -e NOTIFY_EMAIL=me@foo.com -e SMTP_ADDRESS=smtp.mail.tld \
	skylable/sxmonitor
```

Email alerts will be sent to me@foo.com using the smtp.mail.tld mail
server.

## Set the web password 

Access to nagios is protected with basic auth.
Create an account for yourself with:

```bash
docker exec -t -i  sxmonitor su sxmonitor -c "/usr/bin/htpasswd -c /data/htpasswd nagiosadmin"
```

## Upgrades

```bash
docker pull skylable/sxmonitor
docker stop sxmonitor
docker rm sxmonitor
docker start sxmonitor
```

## More info

Nagios plugin home-page: https://exchange.nagios.org/directory/Owner/skylable/1

