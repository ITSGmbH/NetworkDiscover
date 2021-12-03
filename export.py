import sys, getopt

from lib.Storage import Storage
from lib.CsvExport import CsvExport

def discover_usage():
	print('Usage: %s [-p|--pdf] [-n|--name NAME]' % (sys.argv[0]))
	print('\nParameters:')
	print('  -p|--pdf       If given a PDF and not a CSV is exported')
	print('  -n|--name      [network] The name of the scan to export; The database is named after this')


if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'pn:', ['pdf', 'name'])
	except egtopt.GetoptError:
		discover_usage()
		quit(1)

	pdf = False
	name = 'network'
	for opt, arg in opts:
		if opt in ('-p', '--pdf'):
			pdf = True
		elif opt in ('-n', '--name'):
			name = arg

	storage = Storage(name, 0)
	storage.prepare()

	scanid = storage.getLastScanId()

	csv = CsvExport()
	print(csv.export(storage, scanid))
