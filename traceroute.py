#!/usr/bin/python
import json
import logging

import optparse
import socket
import struct
import sys


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
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')

    def create_sockets(self, ttl):
        """
        Sets up sockets necessary for the traceroute.  We need a receiving
        socket and a sending socket.
        """
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, self.udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        return recv_socket, send_socket

    def trace(self, dest_name, port, max_hops):
        route = []
        dest_addr = socket.gethostbyname(dest_name)
        ttl = 1
        while True:
            recv_socket, send_socket = self.create_sockets(ttl)
            recv_socket.bind(("", port))
            send_socket.sendto("", (dest_name, port))
            curr_addr = None
            curr_name = None
            try:
                # socket.recvfrom() gives back (data, address), but we
                # only care about the latter.
                _, curr_addr = recv_socket.recvfrom(512)
                curr_addr = curr_addr[0]  # address is given as tuple
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error:
                pass
            finally:
                send_socket.close()
                recv_socket.close()

            if curr_addr is not None:
                curr_host = "%s (%s)" % (curr_name, curr_addr)
            else:
                curr_host = "*"
            logging.getLogger().info("%d\t%s" % (ttl, curr_host))
            route.append(curr_addr)

            ttl += 1
            if curr_addr == dest_addr or ttl > max_hops:
                break

        return route


if __name__ == "__main__":
    optp = optparse.OptionParser(usage="%prog [options] hostname")
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
    route = traceRoute.trace(dest_name=opts.dest_host,
                             port=int(opts.port),
                             max_hops=int(opts.max_hops))
    value = ">".join(route)
    logger.info("value:%s" % value)
    if not opts.raw_run:
        sender = ZabbixSender(opts.zabbix_server, opts.zabbix_port)
        if opts.zabbix_key is None:
            logging.getLogger().error("zabbix can not be None,plz run with --zabbix_key")
            sys.exit(-1)
        logger.info("send data to zabbix, key=%s   value=%s" % (opts.zabbix_key, value))
        respond = sender.send(opts.zabbix_host, opts.zabbix_key, value)
        logger.info(respond)
