#!/bin/bash
###################
### BEGIN INIT INFO
###################
# Provides:          skeleton
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      N/A
# Short-Description: iptables 
# Description:
#
### END INIT INFO
#
# Author:	Iztok Starc <iztok.starc@fri.uni-lj.si>,
#
# Date:		17. 10. 2011
# Version:	v1.0
#

#############################
### USER CONFIGURABLE SECTION
#############################

set -e
set -x

DESC="netfilter/iptables firewall on $HOSTNAME"

INET_IFACE="enp0s3"                      # Internet-connected interface
IPADDR=`ifconfig $INET_IFACE | grep "inet addr:" | cut -d ":" -f2 | cut -d " " -f1`

MY_ISP="0.0.0.0/0"                   # ISP server & NOC address range
# Your subnet's network address
SUBNET_BASE=`ifconfig $INET_IFACE | grep "inet addr:" | cut -d ":" -f4 | cut -d " " -f1`
# Your subnet's broadcast address
SUBNET_BROADCAST=`ifconfig $INET_IFACE | grep "inet addr:" | cut -d ":" -f3 | cut -d " " -f1`
PRIVPORTS="0:1023"                   # well-known, privileged port range
UNPRIVPORTS="1024:65535"             # unprivileged port range

# DNS server 1
NAMESERVER=`nmcli dev show $INET_IFACE | grep IP4.DNS | cut -d ":" -f2 | tail --lines=1 | tr -d '[[:space:]]'`


#################################
### END USER CONFIGURABLE SECTION
#################################

#
#	Function that starts the daemon/service.
#
d_start() {

### No forwarding
#echo 0 > /proc/sys/net/ipv4/ip_forward
### Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable broadcast echo Protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 

# Enable TCP SYN Cookie Protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance 
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo 0 > $f
done
# Don't send Redirect Messages 
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
    echo 0 > $f
done

##################
### Default policy
##################

# Disable INPUT before changing iptables
iptables --policy INPUT DROP
# Disable OUTPUT before changing iptables
iptables --policy OUTPUT DROP
# Disable FORWARD before changing iptables
iptables --policy FORWARD DROP


###################
### Clear old rules
###################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush
# Delete any user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
# Reset all counters to zero
iptables -Z

#########################################
### netfilter/iptables rules
#########################################

# Resources

# netfilter/iptables
#  http://book.chinaunix.net/special/ebook/Linux_Firewalls3e
#  http://iptables-tutorial.frozentux.net/iptables-tutorial.html
#  http://www.yolinux.com/TUTORIALS/LinuxTutorialIptablesNetworkGateway.html

# BASH:
#  http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
#  http://tldp.org/LDP/abs/html/

### Allow all trafic on localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

### Stateful firewall assignments

# (1) Allow all incoming packets that belong to ESTABLISHED or RELATED connections.
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# (2) TODO: Allow all outgoing packets that belong to ESTABLISHED or RELATED connections.
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# (3) Allow outgoing DNS requests to the DNS server in variable NAMESERVER
iptables -A OUTPUT -p udp -d $NAMESERVER --dport 53 -m state --state NEW -j ACCEPT

# (4) TODO: Allow outgoing SSH connections to remote SSH servers
#iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# (5) TODO: Allow incomming connections to local SSH server
#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# (6) TODO: Allow outgoing HTTP requests 
#iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# (7) TODO: Allow incoming HTTP requests destined to local HTTP server
#iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# (8) TODO: Allow outgoing HTTPS requests 
#iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# (9) TODO: Allow incoming HTTPS requests destined to local HTTP server
#iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# (10) TODO: Allow outgoing ping requests
iptables -A OUTPUT -p icmp --icmp-type 8 -m state --state NEW -j ACCEPT

# (11) TODO: Allow incoming ping requests
iptables -A INPUT -p icmp --icmp-type 8 -m state --state  NEW -j ACCEPT

# (12) TODO: Compress rules 4-9 into two iptables commands using
# "-m multiport" and "--ports" switches.
# Make sure to comment rules 4-9 before testing.
iptables -A OUTPUT -p tcp -m multiport --dports 22,80,443 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 22,80,443 -m state --state NEW -j ACCEPT

### FORWARDING RULES

# Do NAT for internet-bound traffic
iptables -t nat -A POSTROUTING -o $INET_IFACE -j MASQUERADE

FB_IP=185.60.216.35
FB_IPS=31.13.90.36

iptables -A FORWARD -d $FB_IP -j REJECT 
iptables -A FORWARD -s $FB_IP -j REJECT

iptables -A FORWARD -s $FB_IPS -j DROP 
iptables -A FORWARD -d $FB_IPS -j DROP 

#iptables -A FORWARD -p tcp -m tcp --sport 443 -m string --string "facebook" --algo bm -j DROP
#iptables -A FORWARD -p tcp -m tcp --sport 80 -m string --string "facebook" --algo bm -j DROP
#iptables -A FORWARD -p tcp -m tcp --dport 443 -m string --string "facebook" --algo bm -j DROP
#iptables -A FORWARD -p tcp -m tcp --dport 80 -m string --string "facebook" --algo bm -j DROP



# (13) TODO: Allow routing of packets that belong to ESTABLISHED or RELATED connections.
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# (14) Forward pings
iptables -A FORWARD -p icmp --icmp-type echo-request -m state --state NEW  -j ACCEPT

# (15) Forward DNS requests from subnets to Internet and permit in corresponding responses
iptables -A FORWARD -o $INET_IFACE -p udp -m multiport --ports 53 -m state --state NEW -j ACCEPT

# (16) TODO: Forward HTTP, HTTPS and SSH traffic from client_subnet to Internet and to server_subnet
iptables -A FORWARD -p tcp --dport 22 -s "172.16.0.2" -d "10.0.0.2" -m state --state NEW -j ACCEPT
iptables -A FORWARD -p tcp --dport 22 -s "10.0.0.2" -d "172.16.0.2" -m state --state NEW -j ACCEPT

iptables -A FORWARD -p tcp -m multiport --dports 22,80,443 -m state --state NEW -j ACCEPT



}

#
#	Function that stops the daemon/service.
#
d_stop() {
##################
### Default policy
##################

# Disable INPUT before changing iptables
iptables --policy INPUT DROP
# Disable OUTPUT before changing iptables
iptables --policy OUTPUT DROP
# Disable FORWARD before changing iptables
iptables --policy FORWARD DROP

###################
### Clear old rules
###################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush
# Delete any user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
# Reset all counters to zero
iptables -Z

####################
### Set up new rules
####################
# Disable INPUT
iptables --policy INPUT DROP
# Disable OUTPUT
iptables --policy OUTPUT DROP
# Disable FORWARD
iptables --policy FORWARD DROP
}

d_reset() {
##################
### Default policy
##################

# Disable INPUT before changing iptables
iptables --policy INPUT DROP
# Disable OUTPUT before changing iptables
iptables --policy OUTPUT DROP
# Disable FORWARD before changing iptables
iptables --policy FORWARD DROP

###################
### Clear old rules
###################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush
# Delete any user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
# Reset all counters to zero
iptables -Z

####################
### Set up new rules
####################
# Enable INPUT
iptables --policy INPUT ACCEPT
# Enable OUTPUT
iptables --policy OUTPUT ACCEPT
# Enable FORWARD
iptables --policy FORWARD ACCEPT
}

case "$1" in
  start)
	echo -n "Starting $DESC"
	d_start
	echo "."
	;;
  stop)
	echo -n "Stopping $DESC"
	d_stop
	echo "."
	;;
  restart|force-reload)
	echo -n "Restarting $DESC"
	d_start
	echo "."
	;;
  reset)
	echo -n "Reset $DESC"
        d_reset
        echo "."
        ;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|reset|restart|force-reload}" >&2
	exit 3
	;;
esac

exit 0
