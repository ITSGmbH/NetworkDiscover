import sys, getopt
import time
import json

from lib.Storage import Storage
from lib.Syslog import Syslog
from lib.Logger import Logger
from lib.Scanner import Scanner
from lib.LocalNet import LocalNet
from lib.TraceRoute import TraceRoute
from lib.HostDetail import HostDetail

def discover_usage():
	print('Usage: %s [-t|--target A.B.C.D[/E][,SECOND,THIRD,...]] [-s|--simple] [-n|--name NAME] [-d|--device DEVICE] [-h|--hops MAX_NUM_HOPS=10] [-r|--repeated SECONDS=0]' % (sys.argv[0]))
	print('\nParameters:')
	print('  -h|--help                Show this help')
	print('  -t|--target    [local]   List of hosts and/or networks to discover and scan')
	print('                           You can give multiple targets/networks by concat them with a comma \',\'')
	print('                           If this parameter is not given, all local networks on the given device are used')
	print('  -s|--simple    [false]   Don\'t do full scan, no Port- and no CVE-Scan')
	print('  -m|--max       [10]      Maximum number of hops for traceroute')
	print('  -n|--name      [network] Give this scan an name; The database is named after this')
	print('  -d|--device    []        Perform all scans on this device and not let the system choose it automatically')
	print('  -l|--syslog    []        Send log messages to this syslog server')
	print('  -p|--port      [514]     Port where the syslog-server listens on')
	print('  -r|--repeated  [0]       Repeaded scan loop every given seconds; If 0, only one scan is performed.')


def config_value(key, value, config):
	if key in ('-t', '--target', 'target') and len(value) > 0:
		config['target'] = value
	elif key in ('-m', '--max', 'hops') and len(value) > 0:
		config['hops'] = int(value)
	elif key in ('-d', '--device', 'device') and len(value) > 0:
		config['device'] = value
	elif key in ('-n', '--name', 'name') and len(value) > 0:
		config['name'] = value
	elif key in ('-s', '--simple', 'simple') and len(value) > 0:
		config['fullscan'] = False if value == 'True' else True
	elif key in ('-l', '--syslog', 'syslog_host', 'syslog') and len(value) > 0:
		config['syslog_host'] = value
	elif key in ('-p', '--port', 'syslog_port', 'port') and len(value) > 0:
		config['syslog_port'] = int(value)
	elif key in ('-r', '--repeated', 'repeated') and len(value) > 0:
		config['repeated'] = int(value)


if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 't:hm:n:d:sl:p:r:', ['target', 'help', 'max', 'name', 'device', 'simple', 'syslog', 'port', 'repeated'])
	except egtopt.GetoptError:
		discover_usage()
		quit(1)

	# Default values
	config = {
		'name': 'network',
		'target': None,
		'hops': 10,
		'device': None,
		'fullscan': True,
		'syslog_host': None,
		'syslog_port': 514,
		'repeated': 0,
	}

	# Configuration
	with open("config.ini", 'r') as file:
		fp = file.read()
		for line in fp.split("\n"):
			if len(line) < 1: continue
			if line[0] == '#': continue
			if line[0] == '[': continue
			(key, val) = line.split("=")
			key = key.strip()
			val = val.strip()
			config_value(key, val, config)

	# Arguments override configuration
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			discover_usage()
			quit(0)
		else:
			config_value(opt, 'True' if opt in ('-s', '--simple') else arg, config)

	while True:
		scanid = int(time.time() * 1000)

		storage = Storage(config.get('name', 'network'), scanid)
		storage.prepare()
		storage.startScan()

		syslog = Syslog(config.get('syslog_host', None), config.get('syslog_port', None)) if config.get('syslog_host', None) != None else None
		log = Logger(storage, syslog, scanid)

		local_net = LocalNet(log, config.get('device', None))
		local_net.discover()

		scan = Scanner(log)
		targets = scan.scan(config.get('target', None), local_net)

		trace = TraceRoute(log, local_net, config.get('hops', 10))
		for host in targets:
			trace.traceRoute(host)
		trace.persist(storage)

		if fullscan:
			detail = HostDetail(log)
			detail.enrich(trace.hosts.keys())
			detail.persist(storage)

		storage.endScan()
		storage.close()

		# Scan once and stop or sleep for a given time and repeate the scan
		del storage, syslog, log, scan, scanid, targets, trace, local_net
		if repeated == 0:
			break
		else:
			time.sleep(repeated)
