import subprocess

from lib.LocalNet import LocalNet

class TraceRoute:
	def __init__(self, logger, local_net, hops):
		self.logger = logger
		self.max_hops = hops
		self.hosts = {}
		self.local_net = local_net
		self.hosts[self.local_net.default_gw] = { 'trace': True, 'nodes': [] }

	def traceRoute(self, host):
		if isinstance(host, dict) and host.get('address', None) != None:
			current = host.get('address')
			self.logger.log('TraceRoute', 'Tracing host: %s' % (current))

			if self.hosts.get(current, None) == None:
				self.hosts[current] = { 'trace': True, 'nodes': [] }

			if current not in self.local_net.neighbours and current != self.local_net.ipv4:
				result = subprocess.Popen(['traceroute', '-n', '-q', '1', '-m', str(self.max_hops), current], stdout=subprocess.PIPE, stderr=None)
				path = [ self.local_net.ipv4 ] if self.local_net.ipv4 != None else []
				for line in result.stdout:
					line = line.decode('utf-8').strip().split()
					path = self.processHostLine(line, path, current)

			elif current != self.local_net.default_gw and current not in self.hosts.get(self.local_net.default_gw).get('nodes'):
				self.hosts.get(self.local_net.default_gw).get('nodes').append(current)

	def processHostLine(self, line, path, host):
		try:
			if line[0].isnumeric():
				num = int(line[0])
				ip = line[1]
				last = path[-1] if len(path) > 0 else None
				if self.hosts.get(last, None) == None:
					self.hosts[last] = { 'trace': False, 'nodes': [] }
				if ip == '*' and self.local_net.default_gw not in path:
					ip = self.local_net.default_gw
				if ip != '*':
					if self.hosts.get(ip, None) == None:
						self.hosts[ip] = { 'trace': True, 'nodes': [] }
					if self.hosts.get(last, None) != None:
						self.hosts.get(last).get('nodes').append(ip)
					path.append(ip)
				elif num == self.max_hops:
					self.hosts.get(host)['trace'] = False
					self.hosts.get(last).get('nodes').append(host)
		except ValueError:
			pass
		return path

	def persist(self, storage):
		for key in self.hosts:
			host = self.hosts.get(key)
			left = storage.get('hosts', [ 'id' ], [ ('ip=?', key) ])
			if len(left) == 0:
				storage.insert('hosts', { 'ip': key, 'scan': storage.scan })
				left = storage.get('hosts', [ 'id' ], [ ('ip=?', key) ])
			storage.insert('hosts_history', { 'host_id': left[0][0], 'scan': storage.scan })

		for key in self.hosts:
			left = storage.get('hosts_history,hosts', [ 'hosts_history.id' ], [ ('hosts.ip=?', key), ('hosts_history.host_id=hosts.id', ), ('hosts_history.scan=?', storage.scan) ])[0][0]

			for node in self.hosts.get(key).get('nodes'):
				right = storage.get('hosts_history,hosts', [ 'hosts_history.id' ], [ ('hosts.ip=?', node), ('hosts_history.host_id=hosts.id', ), ('hosts_history.scan=?', storage.scan) ])[0][0]
				check = storage.get('routing', [ 'left', 'right' ], [ ('left=?', left), ('right=?', right) ])
				if len(check) == 0:
					storage.insert('routing', { 'left': left, 'right': right })
