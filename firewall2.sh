#!/bin/bash

##########################
# Firewall para Asterisk #
# por José Pastor López  #
# jlopez.mail@gmail.com  #
##########################

# DEFINICION DE VARIABLES
dev_int="eth0"
dev_ext="eth2"
dev_vpn="tun0"
i="/sbin/iptables"
ipsbloqueadas="/root/ipsbloqueadas.txt"

# COMIENZO DE FIREWALL ESTANDAR

# LIMPIEZA DEL FIREWALL
$i -F

# ESTADO FINAL DE LAS REGLAS POR DEFAULT
$i -P INPUT DROP
$i -P OUTPUT DROP
$i -P FORWARD DROP

# (3)a la interface lo (localhost) se le permite todo
$i -A INPUT -i lo -j ACCEPT
$i -A OUTPUT -o lo -j ACCEPT

# Este parte del script lee todas las ips bloqueadas por fail2ban y las pone en un archivo ipsbloqueadas.txt
# para que no se vuelvan a conectar una vez flusheado el firewall
$i -L fail2ban-SSH -n | grep all | grep -v 0.0.0.0 | awk '{print $2 }' >> ipsbloqueadas.txt-tmp
$i -L fail2ban-ASTERISK -n | grep all | grep -v 0.0.0.0 | awk '{print $2 }' >> ipsbloqueadas.txt-tmp
sort ipsbloqueadas.txt-tmp | uniq >> $ipsbloqueadas
rm ipsbloqueadas.txt-tmp

# Leo todas las IPs bloqueadas
for p in $(cat $ipsbloqueadas); do
        iptables -A INPUT -s $p -j DROP
        iptables -A OUTPUT -d $p -j DROP
done;

#PERMITIMOS PUERTO 22
#$i -A INPUT -p tcp --dport 22 -j ACCEPT
#$i -A OUTPUT -p tcp --sport 22 -j ACCEPT
$i -A INPUT -i $dev_int -p tcp --dport 22 -j ACCEPT
$i -A OUTPUT -o $dev_int -p tcp --sport 22 -j ACCEPT

#PERMITIMOS PUERTO 123 (NTP)
$i -A OUTPUT -p tcp --dport 123 -j ACCEPT
$i -A INPUT -p tcp --sport 123 -j ACCEPT

#More security:
#Block access for account scanners like 'User-Agent: friendly-scanner'
#NOTICE: The rules must inserted into the chain at the front to make them work
#properly.
#(If you want to merge the rules into you ruleset make sure they are chained before
#iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT )

$i -I INPUT -p udp -m udp --dport 5060 -m string --string "REGISTER sip:" --algo bm -m recent --set --name VOIP --rsource
$i -I INPUT -p udp -m udp --dport 5060 -m string --string "REGISTER sip:" --algo bm -m recent --update --seconds 60 --hitcount 12 --rttl --name VOIP --rsource -j DROP 
$i -I INPUT -p udp -m udp --dport 5060 -m string --string "INVITE sip:" --algo bm -m recent --set --name VOIPINV --rsource 
$i -I INPUT -p udp -m udp --dport 5060 -m string --string "INVITE sip:" --algo bm -m recent --update --seconds 60 --hitcount 12 --rttl --name VOIPINV --rsource -j DROP 
$i -I INPUT -p udp -m hashlimit --hashlimit 6/sec --hashlimit-mode srcip,dstport --hashlimit-name tunnel_limit -m udp --dport 5060 -j ACCEPT 
#$i -I INPUT -p udp -m udp --dport 5060 -j DROP ## ESTA REGLA SE AGREGA CREO PORQUE EL FIREWALL CONSIDERA SER POLICY ACCEPT

# (4) evitamos ataques syn-flood limitando el acceso de paquetes nuevos
# desde internet a solo 4 por segundo y los demas se descartan
#$i -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j  DROP

# (5) se evitan paquetes tcp que sean nuevos y que no tengan el flag SYN
# es decir, hay ataques o escaneos que llegan como conexiones nuevas
# pero sin ser paquetes syn, definitivamente no nos interesan
$i -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# (7) por ultimo las dos siguientes reglas permiten salir del equipo 
# (output) conexiones nuevas que nosotros solicitamos, conexiones establecidas
# y conexiones relacionadas, y deja entrar (input) solo conexiones establecidas
# y relacionadas.
$i -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$i -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


#PERMITIMOS PUERTO HTTP DESDE PLACA INTERNA
$i -A INPUT -i $dev_int -p tcp --dport 80 -j ACCEPT
$i -A OUTPUT -o $dev_int -p tcp --sport 80 -j ACCEPT

#PERMITIMOS PUERTO DNS
$i -A INPUT -i $dev_ext -p udp --sport 53 -j ACCEPT
$i -A OUTPUT -o $dev_ext -p udp --dport 53 -j ACCEPT

#PERMITIMOS PUERTO HTTPS DESDE PLACA INTERNA
$i -A INPUT -i $dev_int -p tcp --dport 443 -j ACCEPT
$i -A OUTPUT -o $dev_int -p tcp --sport 443 -j ACCEPT

# PROTOCOLO SIP EN PUERTO UDP 5060
# ACA ESTA ABIERTO DESDE EL 5004 AL 5082 PORQUE ESTA EN PRODUCCION CALIENTE Y NO QUEREMOS PERDERLO
# SI FUNCIONA LO IREMOS CERRANDO
# ALGUNOS SERVICIOS REQUIEREN EL PUERTO TCP TAMBIEN, POR ESO LO AGREGO
$i -A INPUT -p udp -m udp --dport 5004:5082 -j ACCEPT
$i -A INPUT -p tcp -m tcp --dport 5004:5082 -j ACCEPT
$i -A OUTPUT -p udp -m udp --sport 5004:5082 -j ACCEPT
$i -A OUTPUT -p tcp -m tcp --sport 5004:5082 -j ACCEPT

# PROTOCOLO IAX2
$i -A INPUT -p udp -m udp --dport 4569 -j ACCEPT

# PROTOCOLO IAX
$i -A INPUT -p udp -m udp --dport 5036 -j ACCEPT

# STREAMING DE MEDIOS RTP
$i -A INPUT -p udp -m udp --dport $(grep rtpstart /etc/asterisk/rtp.conf | awk -F = '{print $2}'):$(grep rtpend /etc/asterisk/rtp.conf | awk -F = '{print $2}') -j ACCEPT
$i -A OUTPUT -p udp -m udp --sport $(grep rtpstart /etc/asterisk/rtp.conf | awk -F = '{print $2}'):$(grep rtpend /etc/asterisk/rtp.conf | awk -F = '{print $2}') -j ACCEPT

# MGCP - if you use media gateway control protocol in your configuration
#$i -A INPUT -p udp -m udp --dport 2727 -j ACCEPT

# REGLA CONTRA IP DE TELMEX DE TELMEX
$i -A INPUT -s 154.0.185.114 -j ACCEPT

# CONSULTAR UN MYSQL EXTERNO
$i -A INPUT -p tcp --sport 3306 -j ACCEPT
$i -A OUTPUT -p tcp --dport 3306 -j ACCEPT

