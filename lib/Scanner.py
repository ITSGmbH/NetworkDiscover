import xml.sax, subprocess, tempfile

class Scanner(xml.sax.ContentHandler):
	def __init__(self):
		self.current = {}
		self.hosts = []
		self.it = 0
		self.tmp = tempfile.TemporaryDirectory()

	def __del__(self):
		if isinstance(self.tmp, tempfile.TemporaryDirectory):
			self.tmp.cleanup()

	def endElement(self, tag):
		if tag == 'host':
			self.hosts.append(self.current)
			self.current = {}

	def startElement(self, tag, attrs):
		if tag == 'host':
			self.current = {
				'address': None,
				'mac': None,
				'vendor': None
				}

		elif tag == 'address' and attrs.get('addrtype') == 'ipv4':
			self.current['address'] = attrs.get('addr')

		elif tag == 'address' and attrs.get('addrtype') == 'mac':
			self.current['mac'] = attrs.get('addr')
			self.current['vendor'] = attrs.get('vendor')

	def scan(self, target):
		out = self.tmp.name + '/targets.xml'
		return_value = subprocess.call(['nmap', '-sn', '-oX', out, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		if return_value == 0:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_namespaces, False)
			parser.setContentHandler(self)
			parser.parse(out)

	def getHosts(self):
		return self.hosts

	def next(self):
		if self.it < len(self.hosts):
			self.it += 1
			return self.hosts[self.it - 1]
		return None

	def rewind(self):
		self.it = 0

