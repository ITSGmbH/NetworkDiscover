import time

class Logger:
	def __init__(self, storage, scan_id):
		self.storage = storage
		self.scan_id = scan_id

	def info(self, origin, msg):
		self.store('info', origin, msg)

	def log(self, origin, msg):
		self.store('log', origin, msg)

	def error(self, origin, msg):
		self.store('error', origin, msg)

	def debug(self, origin, msg):
		self.store('debug', origin, msg)

	def warn(self, origin, msg):
		self.store('warn', origin, msg)

	def store(self, severity, origin, msg):
		self.storage.insert('log', {
			'scan': self.scan_id,
			'severity': severity,
			'origin': origin,
			'log': msg
			})
