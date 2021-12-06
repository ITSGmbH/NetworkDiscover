import subprocess

class LocalNet:
	def __init__(self, logger, device):
		self.logger = logger
		self.device = device
		self.neighbours = []
		self.default_gw = None
		self.ipv4 = None
		self.ipv6 = None
		self.networks = []

	def discover(self):
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
		self.logger.log('LocalNet', 'Found local IPv4: %s' % (self.ipv4))
		self.logger.log('LocalNet', 'Found local IPv6: %s' % (self.ipv6))

	def discoverDefaultGateway(self):
		cmd = ['ip', 'route', 'show']
		if self.device != None:
			cmd.extend(['dev', self.device])
		result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)

		for line in result.stdout:
			line = line.decode('utf-8').strip().split()
			if line[0] == 'default':
				self.default_gw = line[2]
				break
		self.logger.log('LocalNet', 'Found default gateway: %s' % (self.default_gw))

	def discoverNeighbourCache(self):
		cmd = ['ip', 'neighbour', 'show']
		if self.device != None:
			cmd.extend(['dev', self.device])
		result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)

		for line in result.stdout:
			line = line.decode('utf-8').strip().split()
			self.neighbours.append(line[0])
			self.logger.log('LocalNet', 'direct neighbour: %s' % (line[0]))

	def discoverNetworks(self):
		cmd = ['ip', 'route', 'list']
		if self.device != None:
			cmd.extend(['dev', self.device])
		result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None)

		for line in result.stdout:
			line = line.decode('utf-8').strip().split()
			self.networks.append(line[0])
			self.logger.log('LocalNet', 'Local network: %s' % (line[0]))
