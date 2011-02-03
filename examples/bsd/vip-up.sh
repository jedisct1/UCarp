#! /bin/sh
exec 2> /dev/null

/sbin/ifconfig "$1" alias "$2" netmask 255.255.255.255
