import xml.sax, subprocess, tempfile, os

class HostDetail(xml.sax.ContentHandler):
	def __init__(self, logger):
		self.logger = logger
		self.current = {}
		self.hosts = {}
		self.hostsOs = {}
		self.currentTarget = None
		self.tmp = tempfile.TemporaryDirectory()

		self._script_vulners = False
		self._script_vulners_tag = None
		self.vulners = {}
		self.currentVuln = {}

	def __del__(self):
		if isinstance(self.tmp, tempfile.TemporaryDirectory):
			self.tmp.cleanup()

	def endElement(self, tag):
		if tag == 'port':
			if self.hosts.get(self.currentTarget, None) == None:
				self.hosts[self.currentTarget] = []
			self.hosts[self.currentTarget].append(self.current)
			self.current = {}

		elif self._script_vulners and tag == 'script':
			self._script_vulners = False

		elif self._script_vulners and tag == 'elem':
			self._script_vulners_tag = None

		elif self._script_vulners and tag == 'table':
			if self.vulners.get(self.currentTarget, None) == None:
				self.vulners[self.currentTarget] = {}

			key = self.current.get('port') + '/' + self.current.get('protocol')
			if self.vulners[self.currentTarget].get(key, None) == None:
				self.vulners[self.currentTarget][key] = []
			self.vulners[self.currentTarget][key].append(self.currentVuln)
			self.currentVuln = {}

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
			self.current['product'] = attrs.get('product', '?') + ' ' + attrs.get('version', '')
		elif tag == 'osmatch':
			self.hostsOs[self.currentTarget] = attrs.get('name') + ' (' + attrs.get('accuracy', '0') + '%)'
		elif tag == 'script' and attrs.get('id') == 'vulners':
			self._script_vulners = True
		elif self._script_vulners and tag == 'elem':
			self._script_vulners_tag = attrs.get('key');

	def characters(self, content):
		if self._script_vulners and len(self._script_vulners_tag or '') > 0:
			self.currentVuln[self._script_vulners_tag if self._script_vulners_tag != 'id' else 'type_id'] = content


	def enrich(self, hosts = []):
		for host in hosts:
			self.performPortScan(host)
			self.log(host)

	def performPortScan(self, target):
		self.currentTarget = target
		out = self.tmp.name + '/details_%s.xml' % target
		return_value = subprocess.call(['nmap', '-O', '-sT', '-sV', '--script=vulners.nse', '-oX', out, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		if return_value == 0:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_namespaces, False)
			parser.setContentHandler(self)
			parser.parse(out)
		os.remove(out)

	def log(self, target):
		for ip,hosts in self.hosts.items():
			ports = [ host.get('port') + '/' + host.get('protocol') for host in hosts if host.get('port', None) is not None and host.get('protocol', None) is not None ]
			self.logger.log('HostDetail', 'Host: %s; Found %s open ports: %s' % (ip, len(ports), ', '.join(ports)))

	def persist(self, storage):
		for ip,details in self.hosts.items():
			host_id = storage.get('hosts', [ 'rowid' ], [ ('ip=?', ip, 'AND') ])[0][0]

			last_host_scan = storage.get('hosts_history', [ 'rowid' ], [ ('host_id=?', host_id, 'AND'), ('scan=?', storage.scan, 'AND') ])[0][0] or None
			if last_host_scan == None:
				continue

			storage.update('hosts_history', { 'os': self.hostsOs.get(ip, '') }, [ ('rowid=?', last_host_scan) ])
			for port in details:
				data = port.copy()
				data['host_history_id'] = last_host_scan
				data['scan'] = storage.scan

				storage.insert('ports', data)

				port_id = storage.get('ports', [ 'rowid' ], [ ('host_history_id=?', last_host_scan, 'AND'), ('port=?', data.get('port'), 'AND'), ('protocol=?', data.get('protocol'), 'AND'), ('scan=?', storage.scan, 'AND') ])[0][0] or None
				key = data.get('port') + '/' + data.get('protocol')
				for vuln in self.vulners.get(ip, {}).get(key, []):
					data = vuln.copy()
					data['port_id'] = port_id or 0
					data['scan'] = storage.scan

					storage.insert('cves', data)
					self.logger.log('CVEs', 'Possible Security risk: host: %s; port: %s; %s: %s; cvss: %s' % (ip, key, data.get('type'), data.get('type_id'), data.get('cvss')) )

	def buildInfo(self, storage, scan, hosts):
		info = []
		for host in hosts:
			(host_id, ip_address) = storage.get('hosts', ['id', 'ip'], [ ('ip=?', host) ])[0]
			if host_id == None:
				return info

			(host_scan, host_os) = storage.get('hosts_history', [ 'id', 'os' ], [ ('host_id=?', host_id), ('scan=?', scan) ])[0]
			host_ports = []
			for port_row in storage.get('ports', [ 'rowid', 'port', 'protocol', 'state', 'service', 'product' ], [ ('host_history_id=?', host_scan) ]):
				cves = storage.get('cves', [ 'type', 'type_id', 'cvss', 'is_exploit' ], [ ('port_id=?', port_row[0]) ])
				host_ports.append({
					'port': port_row[1],
					'protocol': port_row[2],
					'state': port_row[3],
					'service': port_row[4],
					'product': port_row[5],
					'cves': [ { 'database': cve[0], 'id': cve[1], 'cvss': cve[2], 'exploit': cve[3].lower() == 'true' } for cve in cves ]
					})

			info.append({
				'ip': ip_address,
				'os': host_os,
				'scan_timestamp': scan,
				'ports': host_ports
				})

		return info
