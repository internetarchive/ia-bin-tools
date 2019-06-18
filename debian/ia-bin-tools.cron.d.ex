#
# Regular cron jobs for the ia-bin-tools package
#
0 4	* * *	root	[ -x /usr/bin/ia-bin-tools_maintenance ] && /usr/bin/ia-bin-tools_maintenance
