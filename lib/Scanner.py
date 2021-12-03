import xml.sax, subprocess, tempfile

class Scanner(xml.sax.ContentHandler):
	def __init__(self, logger):
		self.logger = logger
		self.current = {}
		self.hosts = []
		self.tmp = tempfile.TemporaryDirectory()

	def __del__(self):
		if isinstance(self.tmp, tempfile.TemporaryDirectory):
			self.tmp.cleanup()

	def endElement(self, tag):
		if tag == 'host':
			self.logger.log('Scanner', 'Host discoverd: %s' % (self.current.get('address')))
			self.hosts.append(self.current)
			self.current = {}

	def startElement(self, tag, attrs):
		if tag == 'host':
			self.current = { 'address': None }

		elif tag == 'address' and attrs.get('addrtype') == 'ipv4':
			self.current['address'] = attrs.get('addr')

	def scan(self, target):
		self.logger.log('Scanner', 'Start host discover')
		out = self.tmp.name + '/targets.xml'
		return_value = subprocess.call(['nmap', '-sn', '-oX', out] + target.split(','), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		if return_value == 0:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_namespaces, False)
			parser.setContentHandler(self)
			parser.parse(out)

		self.logger.log('Scanner', 'Discovered %s hosts' % (len(self.hosts)))
		return self.hosts
