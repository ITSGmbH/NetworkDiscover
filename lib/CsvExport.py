from datetime import datetime

from lib.Graph import Graph
from lib.HostDetail import HostDetail

class CsvExport:
	def __init__(self):
		self.lines = []

	def prepare(self, details):
		self.lines = [ ';'.join([
			'date',
			'ip',
			'os',
			'port',
			'protocol',
			'state',
			'service',
			'product',
			'database',
			'id',
			'cvss',
			'exploit'
			]) ]

		for host in details:
			date = datetime.utcfromtimestamp(host.get('scan_timestamp')/1000).strftime('%Y-%m-%d %H:%M:%S')
			for port in host.get('ports'):
				for cve in port.get('cves'):
					self.lines.append(';'.join([
						date,
						host.get('ip'),
						'"' + host.get('os') + '"',
						str(port.get('port')),
						port.get('protocol'),
						port.get('state'),
						port.get('service'),
						'"' + port.get('product') + '"',
						cve.get('database'),
						'"' + cve.get('id') + '"',
						str(cve.get('cvss')),
						'1' if cve.get('exploit') else '0'
						]))
				else:
					self.lines.append(';'.join([
						date,
						host.get('ip'),
						'"' + host.get('os') + '"',
						str(port.get('port')),
						port.get('protocol'),
						port.get('state'),
						port.get('service'),
						'"' + port.get('product') + '"',
						'',
						'',
						'',
						''
						]))

	def export(self, storage, scan):
		graph = Graph()
		detail = HostDetail(None)

		hosts = graph.buildHosts(storage, scan)
		details = detail.buildInfo(storage, scan, hosts)

		self.prepare(details)
		return '\n'.join(self.lines)
