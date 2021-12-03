import sys, getopt
import time
import json

from lib.Storage import Storage
from lib.Logger import Logger
from lib.Scanner import Scanner
from lib.TraceRoute import TraceRoute
from lib.HostDetail import HostDetail

def discover_usage():
	print('Usage: %s -t|--target A.B.C.D[/E][,SECOND,THIRD,...] [-s|--simple] [-n|--name NAME] [-d|--device DEVICE] [-h|--hops MAX_NUM_HOPS=10]' % (sys.argv[0]))
	print('\nParameters:')
	print('  -t|--target              List of hosts and networks to discover and scan')
	print('                           You can give multiple targets/networks by concat them with a semicolone \';\'')
	print('  -s|--simple    [false]   Don\'t do full scan, no Port- and no CVE-Scan')
	print('  -n|--name      [network] Give this scan an name; The database is named after this')
	print('  -d|--device    []        Perform all scans on this device and not let the system choose it automatically')
	print('  -h|--hops      [10]      Maximum number of hops for traceroute')


if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 't:h:n:d:s', ['target', 'hops', 'name', 'device', 'simple'])
	except egtopt.GetoptError:
		discover_usage()
		quit(1)

	name = 'network'
	target = None
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

	if target == None:
		discover_usage()
		quit(1)

	scanid = int(time.time())

	storage = Storage(name, scanid)
	storage.prepare()
	storage.startScan()

	log = Logger(storage, scanid)

	scan = Scanner(log)
	targets = scan.scan(target)

	trace = TraceRoute(log, hops, device)
	trace.discoverLocalNet()
	for host in targets:
		trace.traceRoute(host)
	trace.persist(storage)

	if fullscan:
		detail = HostDetail(log)
		detail.enrich(trace.hosts.keys())
		detail.persist(storage)

	storage.endScan()
