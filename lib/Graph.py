import graphviz

class Graph:
	def __init__(self):
		self.graph = graphviz.Digraph('Network', filename='network.gv', node_attr={'color': 'lightblue2', 'style': 'filled'})
		self.graph.attr(size='6,6')
		self.maxCount = 0

	def prepare(self, hosts):
		for host, attrs in hosts.items():
			nodes = set(attrs.get('nodes', []))
			self.maxCount = max(self.maxCount, len(nodes))
			for node in nodes:
				self.graph.node(node, '%s\nOS: %s' % (node, '?'))
				self.graph.edge(host, node)

	def show(self, hosts):
		self.prepare(hosts)
		unflatten = self.graph.unflatten(stagger=int(self.maxCount/5))
		unflatten.view()

