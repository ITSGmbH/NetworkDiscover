import graphviz

class Graph:
	def __init__(self):
		self.maxCount = 0

	def prepare_graph(self, name):
		self.graph = graphviz.Graph('Network: %s' % name, filename='%s.gv' % (name), format='pdf', node_attr={
			'color': 'lightblue2',
			'style': 'filled',
			'fontsize': '11',
			'labelfloat': 'true',
			'labelloc': 'c'
			})
		#self.graph.attr(size='6,6')

	def prepare(self, hosts):
		for host, attrs in hosts.items():
			nodes = set(attrs.get('nodes', []))
			self.maxCount = max(self.maxCount, len(nodes))

			label = ''
			label_len = 0
			for label_part in attrs.get('os', '').split():
				if label_len > 15:
					label += '\n'
					label_len = 0
				label += label_part + ' '
				label_len += len(label_part) + 1
			self.graph.node(host, '%s\n%s' % (host, label))

			for node in nodes:
				self.graph.edge(host, node)

	def buildHosts(self, storage, scan):
		hosts = {}
		for _h in storage.get('hosts_history', ['host_id', 'os'], [ ('scan=?', scan) ]):
			ip = storage.get('hosts', [ 'ip' ], [ ( 'id=?', _h[0] ), ( 'ignore=?', '0' ) ])[0][0]
			rights = storage.get('routing,hosts', ['hosts.ip'], [ ('routing.left=?', _h[0]), ('routing.right=hosts.rowid', None) ])

			hosts[ip] = {
				'os': _h[1],
				'nodes': [ right[0] for right in rights if len(right) > 0 ]
				}
		return hosts

	def build(self, storage, scan):
		hosts = self.buildHosts(storage, scan)
		self.prepare_graph(storage.name)
		self.prepare(hosts)
		return self.graph

	def export(self, storage, scan):
		graph = self.build(storage, scan)
		return graph.pipe(format='pdf')

	def show(self, storage, scan):
		graph = self.build(storage, scan)
		graph.view()
