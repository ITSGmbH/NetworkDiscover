import sys, getopt
import time
import json

from lib.Config import Config
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


if __name__ == '__main__':
	try:
		opts, args = getopt.getopt(sys.argv[1:], 't:hm:n:d:sl:p:r:', ['target', 'help', 'max', 'name', 'device', 'simple', 'syslog', 'port', 'repeated'])
	except egtopt.GetoptError:
		discover_usage()
		quit(1)

	# Default values
	config = Config().load()

	# Arguments override configuration
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			discover_usage()
			quit(0)
		else:
			config.set(opt, 'True' if opt in ('-s', '--simple') else arg)
	config.save()

	while True:
		config.start_run()
		scanid = int(time.time() * 1000)
		print("Scan started with id %s" % (scanid))

		storage = Storage(config.get('name', 'network'), scanid)
		storage.prepare()
		storage.startScan()

		syslog_host = config.get('syslog_host', None)
		syslog = Syslog(syslog_host, config.get('syslog_port', None)) if syslog_host not in (None, '') else None
		log = Logger(storage, syslog, scanid)

		device = config.get('device', None)
		local_net = LocalNet(log, device if device not in (None, '') else None)
		local_net.discover()

		target = config.get('target', None)
		scan = Scanner(log)
		targets = scan.scan(target if target not in (None, '') else None , local_net)

		trace = TraceRoute(log, local_net, config.get('hops', 10))
		for host in targets:
			trace.traceRoute(host)
		trace.persist(storage)

		if config.get('fullscan', True):
			detail = HostDetail(log)
			detail.enrich(trace.hosts.keys())
			detail.persist(storage)

		storage.endScan()
		storage.close()

		# Scan once and stop or sleep for a given time and repeate the scan
		del storage, syslog, log, scan, scanid, targets, trace, local_net

		config.pause_run()

		pause = 10
		timeout = int(config.get('repeated',  0))

		if timeout > 0:
			print("Next scan in %s seconds; Check every %s seconds for a trigger" % (timeout, pause))
		else:
			print("Wait for a trigger in the UI for the next scan; Check every %s seconds for a trigger" % (pause))

		while timeout >= 0:
			time.sleep(pause)
			if int(config.get('repeated',  0)) != 0:
				timeout = timeout - pause

			if config.is_triggered():
				timeout = -1

		config.reload()
