import time

from lib.Syslog import Syslog

class Logger:
	def __init__(self, storage, syslog, scan):
		self.storage = storage
		self.syslog = syslog
		self.scan = scan

	def info(self, origin, msg):
		self.store('info', origin, msg)

	def log(self, origin, msg):
		self.store('notice', origin, msg)

	def error(self, origin, msg):
		self.store('err', origin, msg)

	def debug(self, origin, msg):
		self.store('debug', origin, msg)

	def warn(self, origin, msg):
		self.store('warning', origin, msg)

	def alert(self, origin, msg):
		self.store('alert', origin, msg)

	def critical(self, origin, msg):
		self.store('crit', origin, msg)

	def store(self, severity, origin, msg):
		if self.storage != None:
			self.storage.insert('log', {
				'scan': self.scan,
				'severity': severity,
				'origin': origin,
				'log': msg
				})

		if self.syslog != None:
			self.syslog.log('[%s] %s' % (origin, msg), Syslog.LEVEL[severity])
