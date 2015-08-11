#!/usr/bin/python
import json
import logging

import optparse
import os
import re
import socket
import struct
import sys
import subprocess


class ZabbixSender:
    def __init__(self, server_host, server_port=10051):
        self.server_ip = socket.gethostbyname(server_host)
        self.server_port = server_port

    def send(self, host, key, value):
        DATA = r'''{
                    "request":"sender data",
                    "data":[
                        {
                        "host":"%s",
                        "key":"%s",
                        "value":"%s"
                        }
                    ]
                }
                ''' % (host, key, value)
        HEADER = '''ZBXD\1%s%s'''
        data_length = len(DATA)
        data_header = struct.pack('i', data_length) + '\0\0\0\0'

        data_to_send = HEADER % (data_header, DATA)

        # here really should come some exception handling
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server_ip, self.server_port))


        # send the data to the server
        sock.send(data_to_send)

        # read its response, the first five bytes are the header again
        response_header = sock.recv(5)
        if not response_header == 'ZBXD\1':
            raise ValueError('Got invalid response')

        # read the data header to get the length of the response
        response_data_header = sock.recv(8)
        response_data_header = response_data_header[:4]  # we are only interested in the first four bytes
        response_len = struct.unpack('i', response_data_header)[0]

        # read the whole rest of the response now that we know the length
        response_raw = sock.recv(response_len)

        sock.close()

        response = json.loads(response_raw)

        return response


class TraceRoute:
    def trace(self, dest_name):
        f = os.popen('/bin/tracepath %s' % dest_name)
        route = {}
        for line in f.readlines():
            logging.getLogger().debug(line)
            m = re.search("(\d):.*\((\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", line)
            if m:
                route[m.group(1).strip()] = m.group(2).strip()
                logging.getLogger().debug("key:%s   value:%s" % (m.group(1), m.group(2)))

        return route


if __name__ == "__main__":

    optp = optparse.OptionParser(usage="%prog -D dest_host -z zabbix_server -H zabbix_host -k zabbix_key")
    # Output verbosity options.
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)

    optp.add_option("-p", "--port", dest="port",
                    help="Port to use for socket connection [default: %default]",
                    default=33434, metavar="PORT")
    optp.add_option("-m", "--max-hops", dest="max_hops",
                    help="Max hops before giving up [default: %default]",
                    default=30, metavar="MAXHOPS")

    optp.add_option("-z", "--zabbix_server", dest="zabbix_server", default="127.0.0.1",
                    help="zabbix server")

    optp.add_option("-P", "--zabbix_port", dest="zabbix_port", type="int", default=10051,
                    help="zabbix port")

    optp.add_option("-k", "--zabbix_key", dest="zabbix_key",
                    help="zabbix port")

    optp.add_option("-H", "--zabbix_host", dest="zabbix_host",
                    help="zabbix host")

    optp.add_option("-R", "--raw_run", dest="raw_run",
                    help="just do traceroute,don't submit to zabbix")

    optp.add_option("-D", "--dest_host", dest="dest_host",
                    help="the target to trace")

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')
    logger = logging.getLogger()

    traceRoute = TraceRoute()
    route = traceRoute.trace(dest_name=opts.dest_host)
    logging.getLogger().info(route)
    value = []

    for i in range(1, 32):
        if route.get(str(i)):
            value.append(route.get(str(i)))

    logger.info("value:%s" % value)
    val = ">".join(value)
    if not opts.raw_run:
        sender = ZabbixSender(opts.zabbix_server, opts.zabbix_port)
        if opts.zabbix_key is None:
            logging.getLogger().error("zabbix can not be None,plz run with --zabbix_key")
            sys.exit(-1)
        logger.info("send data to zabbix, key=%s   value=%s" % (opts.zabbix_key, val))
        respond = sender.send(opts.zabbix_host, opts.zabbix_key, val)
        logger.info(respond)
