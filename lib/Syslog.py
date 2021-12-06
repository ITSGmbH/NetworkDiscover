import socket

class Syslog:
	FACILITY = {
		'kern': 0,
		'user': 1,
		'mail': 2,
		'daemon': 3,
		'auth': 4,
		'syslog': 5,
		'lpr': 6,
		'news': 7,
		'uucp': 8,
		'cron': 9,
		'authpriv': 10,
		'ftp': 11,
		'local0': 16,
		'local1': 17,
		'local2': 18,
		'local3': 19,
		'local4': 20,
		'local5': 21,
		'local6': 22,
		'local7': 23,
	}

	LEVEL = {
		'emerg': 0,
		'alert': 1,
		'crit': 2,
		'err': 3,
		'warning': 4,
		'notice': 5,
		'info': 6,
		'debug': 7
	}

	def __init__(self, host='localhost', port=514):
		self.host = host
		self.port = port

	def log(self, message, level=None, facility=None):
		level = self.LEVEL['notice'] if level == None else level
		facility = self.FACILITY['daemon'] if facility == None else facility
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.sendto('<%d>%s' % ( level + facility * 8, message ), ( self.host, self.port ))
		sock.close()
