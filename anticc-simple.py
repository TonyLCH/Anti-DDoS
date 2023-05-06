import socket
import threading
import re
import time
import logging

class DDoSDefender:
    def __init__(self, host='0.0.0.0', port=80, buffer_size=1024, max_connections=1000,
                 request_limit_per_second=50, ip_limit_per_second=10, max_request_length=4096,
                 max_requests_per_ip=100, connection_timeout=5, ip_ban_time=60, ban_threshold=10,
                 blacklist=None, whitelist=None, log_level=logging.INFO):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.max_connections = max_connections
        self.request_limit_per_second = request_limit_per_second
        self.ip_limit_per_second = ip_limit_per_second
        self.max_request_length = max_request_length
        self.max_requests_per_ip = max_requests_per_ip
        self.connection_timeout = connection_timeout
        self.ip_ban_time = ip_ban_time
        self.ban_threshold = ban_threshold
        self.blacklist = blacklist or []
        self.whitelist = whitelist or []
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        self.ip_counts = {}
        self.request_counts = {}

    def start(self):
        self.logger.info('Starting DDoS defender...')
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_connections)
        self.logger.info('DDoS defender started on {}:{}'.format(self.host, self.port))
        while True:
            client_socket, address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
            client_thread.start()

    def handle_client(self, client_socket, address):
        client_socket.settimeout(self.connection_timeout)
        ip = address[0]
        if self.is_blacklisted(ip):
            self.logger.warning('Blocked connection from blacklisted IP: {}'.format(ip))
            client_socket.close()
            return
        if self.is_whitelisted(ip):
            self.logger.debug('Accepted connection from whitelisted IP: {}'.format(ip))
        else:
            if not self.add_request_count(ip):
                self.logger.warning('Blocked connection from IP {} due to excessive requests: {}'.format(ip, self.request_counts[ip]))
                self.ban_ip(ip)
                client_socket.close()
                return
            if not self.add_ip_count(ip):
                self.logger.warning('Blocked connection from IP {} due to too many connections: {}'.format(ip, self.ip_counts[ip]))
                client_socket.close()
                return
            self.logger.debug('Accepted connection from IP: {}'.format(ip))
        request_data = b''
        while True:
            try:
                request_chunk = client_socket.recv(self.buffer_size)
                if not request_chunk:
                    break
                request_data += request_chunk
                if len(request_data) > self.max_request_length:
                    self.logger.warning('Blocked request from IP {} due to excessive length: {}'.format(ip, len(request_data)))
                    client_socket.close()
                    return
                if not self.add_request_count(ip):
                    self.logger.warning('Blocked request from IP {} due to excessive requests: {}'.format(ip, self.request_counts[ip]))
                    self.ban_ip(ip)
                    client_socket.close()
                    return
                if not self.add_ip_count(ip):
                    self.logger.warning('Blocked request from IP {} due to too many connections: {}'.format(ip, self.ip_counts[ip]))
                    client_socket.close()
                    return
            except socket.timeout:
                self.logger.warning('Connection from IP {} timed out'.format(ip))
                client_socket.close()
                return
        client_socket.close()

    def add_ip_count(self, ip):
        now = time.time()
        if ip not in self.ip_counts:
            self.ip_counts[ip] = 1
            return True
        elif self.ip_counts[ip] < self.max_connections and now - self.ip_counts[ip] >= 1/self.ip_limit_per_second:
            self.ip_counts[ip] += 1
            return True
        else:
            return False

    def add_request_count(self, ip):
        now = time.time()
        if ip not in self.request_counts:
            self.request_counts[ip] = 1
            return True
        elif self.request_counts[ip] < self.max_requests_per_ip and now - self.request_counts[ip] >= 1/self.request_limit_per_second:
            self.request_counts[ip] += 1
            return True
        else:
            return False

    def ban_ip(self, ip):
        if ip in self.ip_counts and self.ip_counts[ip] >= self
        .ban_threshold:
            self.logger.warning('Banning IP {} for {} seconds'.format(ip, self.ip_ban_time))
            self.blacklist.append(ip)
            self.ip_counts.pop(ip)
            t = threading.Thread(target=self.unban_ip, args=(ip,))
            t.start()

    def is_blacklisted(self, ip):
        return ip in self.blacklist

    def is_whitelisted(self, ip):
        return ip in self.whitelist or not self.whitelist

    def unban_ip(self, ip):
        time.sleep(self.ip_ban_time)
        if ip in self.blacklist:
            self.logger.info('Unbanning IP {}'.format(ip))
            self.blacklist.remove(ip)

    def add_to_blacklist(self, ip):
        if ip not in self.blacklist:
            self.logger.info('Adding IP {} to blacklist'.format(ip))
            self.blacklist.append(ip)

    def remove_from_blacklist(self, ip):
        if ip in self.blacklist:
            self.logger.info('Removing IP {} from blacklist'.format(ip))
            self.blacklist.remove(ip)

    def add_to_whitelist(self, ip):
        if ip not in self.whitelist:
            self.logger.info('Adding IP {} to whitelist'.format(ip))
            self.whitelist.append(ip)

    def remove_from_whitelist(self, ip):
        if ip in self.whitelist:
            self.logger.info('Removing IP {} from whitelist'.format(ip))
            self.whitelist.remove(ip)
            print ('''test''')