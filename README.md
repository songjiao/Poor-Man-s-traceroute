基于zabbix_trapper监控机房之间路由变化的工具
===============================================================



        Usage: traceroute.py -D dest_host -z zabbix_server -H zabbix_host -k zabbix_key [Options]
        Options:
          -h, --help            show this help message and exit
          -q, --quiet           set logging to ERROR
          -d, --debug           set logging to DEBUG
          -v, --verbose         set logging to COMM
          -p PORT, --port=PORT  Port to use for socket connection [default: 33434]
          -m MAXHOPS, --max-hops=MAXHOPS
                                Max hops before giving up [default: 30]
          -z ZABBIX_SERVER, --zabbix_server=ZABBIX_SERVER
                                zabbix server
          -P ZABBIX_PORT, --zabbix_port=ZABBIX_PORT
                                zabbix port
          -k ZABBIX_KEY, --zabbix_key=ZABBIX_KEY
                                zabbix port
          -H ZABBIX_HOST, --zabbix_host=ZABBIX_HOST
                                zabbix host
          -R RAW_RUN, --raw_run=RAW_RUN
                                just do traceroute,don't submit to zabbix
          -D DEST_HOST, --dest_host=DEST_HOST
                                the target to trace


##用法：

*  1、先在zabbix里新建一个host，并新建item,入host:network-mon,item:network.traceroute.tobeijing
*  2、在对应的host上新建一个trigger，监控最近收到的数据是否和上次的数据不一样，如果不一样则报警
*  3、在外地机房部署定时脚本，每个300s 执行一次：


        traceroute.py  -D 国内机房的IP -z zabbix_server的IP -H network-mon -k network.traceroute.tobeijing


这样就会每隔五分钟往zabbix server发一次当前路由的数据
