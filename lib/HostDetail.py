import xml.sax, subprocess, tempfile

class HostDetail(xml.sax.ContentHandler):
	def __init__(self):
		self.current = {}
		self.hosts = []
		self.tmp = tempfile.TemporaryDirectory()

	def __del__(self):
		if isinstance(self.tmp, tempfile.TemporaryDirectory):
			self.tmp.cleanup()

	def endElement(self, tag):
		if tag == 'port':
			self.hosts.append(self.current)
			self.current = {}

	def startElement(self, tag, attrs):
		if tag == 'port':
			self.current = {
				'port': attrs.get('portid'),
				'protocol': attrs.get('protocol'),
				'state': None,
				'service': None,
				'product': None
				}
		elif tag == 'state':
			self.current['state'] = attrs.get('state')
		elif tag == 'service':
			self.current['service'] = attrs.get('name')
			self.current['product'] = attrs.get('product')

	def enrich(self, hosts = []):
		for host in hosts:
			self.performPortScan(host)

	def performPortScan(self, target):
		out = self.tmp.name + '/details_%s.xml' % target
		return_value = subprocess.call(['nmap', '-O', '-sT', '-sV', '-sC', '-oX', out, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		if return_value == 0:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_namespaces, False)
			parser.setContentHandler(self)
			parser.parse(out)

		for host in self.hosts:
			host['ip'] = target


	def persist(self, storage):
		for host in self.hosts:
			h = host.copy()
			ip = h.pop('ip', None)

			host_id = storage.get('hosts', [ 'rowid' ], [ ('ip=?', ip, 'AND') ])[0][0]
			h['host'] = host_id

			existing = storage.get('ports', [ 'rowid' ], [ ('host=?', host_id, 'AND'), ('port=?', host.get('port'), 'AND'), ('protocol=?', host.get('protocol'), 'AND') ])
			if len(existing) == 0:
				storage.insert('ports', h)
			else:
				h['last_seen'] = 'CURRENT_TIMESTAMP'
				storage.update('ports', h, [ ('host=?', host_id), ('port=?', host.get('port')), ('protocol=?', host.get('protocol')) ])

