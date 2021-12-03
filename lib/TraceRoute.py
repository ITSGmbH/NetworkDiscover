import subprocess

class TraceRoute:
	def __init__(self, logger, hops, device):
		self.logger = logger
		self.maxHops = hops
		self.device = device
		self.default_gw = None
		self.ipv4 = None
		self.ipv6 = None
		self.hosts = {}
		self.neighbours = []

	def traceRoute(self, host):
		if isinstance(host, dict) and host.get('address', None) != None:
			current = host.get('address')
			self.logger.log('TraceRoute', 'Tracing host: %s' % (current))

			if self.hosts.get(current, None) == None:
				self.hosts[current] = { 'trace': True, 'nodes': [] }

			if current not in self.neighbours and current != self.ipv4:
				result = subprocess.Popen(['traceroute', '-n', '-q', '1', '-m', str(self.maxHops), current], stdout=subprocess.PIPE, stderr=None)
				path = [ self.ipv4 ] if self.ipv4 != None else []
				for line in result.stdout:
					line = line.decode('utf-8').strip().split()
					path = self.processHostLine(line, path, current)

			elif current != self.default_gw and current not in self.hosts.get(self.default_gw).get('nodes'):
				self.hosts.get(self.default_gw).get('nodes').append(current)

	def processHostLine(self, line, path, host):
		try:
			if line[0].isnumeric():
				num = int(line[0])
				ip = line[1]
				last = path[-1] if len(path) > 0 else None
				if self.hosts.get(last, None) == None:
					self.hosts[last] = { 'trace': False, 'nodes': [] }
				if ip == '*' and self.default_gw not in path:
					ip = self.default_gw
				if ip != '*':
					if self.hosts.get(ip, None) == None:
						self.hosts[ip] = { 'trace': True, 'nodes': [] }
					if self.hosts.get(last, None) != None:
						self.hosts.get(last).get('nodes').append(ip)
					path.append(ip)
				elif num == self.maxHops:
					self.hosts.get(host)['trace'] = False
					self.hosts.get(last).get('nodes').append(host)
		except ValueError:
			pass
		return path

	def discoverLocalNet(self):
		self.discoverHost()
		self.discoverDefaultGateway()
		self.discoverNeighbourCache()

	def discoverHost(self):
		cmd = ['ip', 'address', 'show']
		if self.device != None:
			cmd.extend(['dev', self.device])
		result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)

		for line in result.stdout:
			line = line.decode('utf-8').strip().split()
			if line[0] == 'inet':
				self.ipv4 = line[1].split('/')[0]
			elif line[0] == 'inet6':
				self.ipv6 = line[1].split('/')[0]
		self.logger.log('TraceRoute', 'Found local IPv4: %s' % (self.ipv4))
		self.logger.log('TraceRoute', 'Found local IPv6: %s' % (self.ipv6))

	def discoverDefaultGateway(self):
		cmd = ['ip', 'route', 'show']
		if self.device != None:
			cmd.extend(['dev', self.device])
		result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)

		for line in result.stdout:
			line = line.decode('utf-8').strip().split()
			if line[0] == 'default':
				self.default_gw = line[2]
				self.hosts[self.default_gw] = { 'trace': True, 'nodes': [] }
				break
		self.logger.log('TraceRoute', 'Found default gateway: %s' % (self.default_gw))

	def discoverNeighbourCache(self):
		cmd = ['ip', 'neighbour', 'show']
		if self.device != None:
			cmd.extend(['dev', self.device])
		result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)

		for line in result.stdout:
			line = line.decode('utf-8').strip().split()
			self.neighbours.append(line[0])

	def persist(self, storage):
		for key in self.hosts:
			host = self.hosts.get(key)
			left = storage.get('hosts', [ 'rowid' ], [ ('ip=?', key, 'AND') ])
			if len(left) == 0:
				storage.insert('hosts', { 'ip': key, 'scan': storage.scan })

		for key in self.hosts:
			left = storage.get('hosts', [ 'rowid' ], [ ('ip=?', key, 'AND') ])[0][0]
			storage.insert('hosts_history', { 'host_id': left, 'scan': storage.scan })
			for node in self.hosts.get(key).get('nodes'):
				right = storage.get('hosts', [ 'rowid' ], [ ('ip=?', node, 'AND') ])[0][0]
				check = storage.get('routing', [ 'left', 'right' ], [ ('left=?', left, 'AND'), ('right=?', right, 'AND') ])
				if len(check) == 0:
					storage.insert('routing', { 'left': left, 'right': right })
