import sys, getopt
import json

from lib.Scanner import Scanner
from lib.TraceRoute import TraceRoute
from lib.Graph import Graph
from lib.Storage import Storage

if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 't:h:', ['target', 'hops'])
	except egtopt.GetoptError:
		print('Usage: %s -t|--target A.B.C.D[/E] [-n|--name NAME] [-d|--device DEVICE] [-h|--hops MAX_NUM_HOPS=10]' % (sys.argv[0]))
		quit()

	name = 'network'
	target = '127.0.0.1'
	hops = 10
	device = None
	for opt, arg in opts:
		if opt in ('-t', '--target'):
			target = arg
		elif opt in ('-h', '--hops'):
			hops = int(arg)
		elif opt in ('-d', '--device'):
			device = arg
		elif opt in ('-n', '--name'):
			name = arg

	storage = Storage(name)
	storage.prepare()

	scan = Scanner()
	scan.scan(target)

	trace = TraceRoute(hops, device)
	trace.discover()
	for host in scan.getHosts():
		trace.trace(host)
	trace.persist(storage)

	viz = Graph()
	viz.show(trace.hosts)

