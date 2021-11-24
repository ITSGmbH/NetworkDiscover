import sys, getopt
import json

from lib.Scanner import Scanner
from lib.TraceRoute import TraceRoute
from lib.Graph import Graph
from lib.Storage import Storage
from lib.HostDetail import HostDetail

if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 't:h:n:d:s', ['target', 'hops', 'name', 'device', 'simple'])
	except egtopt.GetoptError:
		print('Usage: %s -t|--target A.B.C.D[/E] [-s|--simple] [-n|--name NAME] [-d|--device DEVICE] [-h|--hops MAX_NUM_HOPS=10]' % (sys.argv[0]))
		quit()

	name = 'network'
	target = '127.0.0.1'
	hops = 10
	device = None
	fullscan = True
	for opt, arg in opts:
		if opt in ('-t', '--target'):
			target = arg
		elif opt in ('-h', '--hops'):
			hops = int(arg)
		elif opt in ('-d', '--device'):
			device = arg
		elif opt in ('-n', '--name'):
			name = arg
		elif opt in ('-s', '--simple'):
			fullscan = False

	storage = Storage(name)
	storage.prepare()

	scan = Scanner()
	scan.scan(target)

	trace = TraceRoute(hops, device)
	trace.discover()
	for host in scan.hosts:
		trace.trace(host)
	trace.persist(storage)

	if fullscan:
		detail = HostDetail()
		detail.enrich(trace.hosts.keys())
		detail.persist(storage)

	viz = Graph()
	# Change this to: viz.show(storage)
	# Or first read out all needed information and prepare the data format
	viz.show(trace.hosts)

	#print( json.dumps(detail.hosts, sort_keys=False, indent=2) )

