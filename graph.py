import sys, getopt

from lib.Graph import Graph
from lib.Storage import Storage

def discover_usage():
	print('Usage: %s [-n|--name NAME]' % (sys.argv[0]))
	print('\nParameters:')
	print('  -n|--name      [network] The name of the scan to create a vizualization of; The database is named after this')
	print('  -s|--scan      [] The scan to show the graph of, this is an integer/timestamp')


if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'n:s:', ['name', 'scan'])
	except getopt.GetoptError:
		discover_usage()
		quit(1)

	name = 'network'
	scan = 0
	for opt, arg in opts:
		if opt in ('-n', '--name'):
			name = arg
		elif opt in ('-s', '--scan'):
			scan = int(arg)

	storage = Storage(name, 0)
	storage.prepare()

	scanid = storage.getLastScanId() if scan == 0 else scan

	viz = Graph()
	viz.show(storage, scanid)
