import os

from simple_http_server import controller
from simple_http_server import request_map
from simple_http_server import Response
from simple_http_server import MultipartFile
from simple_http_server import Parameter
from simple_http_server import Parameters
from simple_http_server import Header
from simple_http_server import JSONBody
from simple_http_server import HttpError
from simple_http_server import StaticFile
from simple_http_server import Headers
from simple_http_server import Cookies
from simple_http_server import Cookie
from simple_http_server import Redirect
from simple_http_server import ModelDict
from simple_http_server import PathValue

import simple_http_server.server as server

from lib.Storage import Storage
from lib.Graph import Graph
from lib.HostDetail import HostDetail
from lib.CsvExport import CsvExport

@controller
class HttpControler:
	def __init__(self) -> None:
		self._name = "controller object"

	@request_map('/', method='GET')
	def index_handler(self):
		return StaticFile('http/index.html', 'text/html; charset=utf-8')

	@request_map('/js/*', method='GET')
	def js_handler(self, path_value=PathValue()):
		return StaticFile('http/js/%s' % (path_value), 'application/javascript; charset=utf-8')

	@request_map('/css/*', method='GET')
	def css_handler(self, path_value=PathValue()):
		return StaticFile('http/css/%s' % (path_value), 'text/css; charset=utf-8')

	@request_map('/img/*', method='GET')
	def img_handler(self, path_value=PathValue()):
		return StaticFile('http/img/%s' % (path_value), 'image/png; charset=utf-8')

	@request_map('/api/*', method='GET')
	def api_handler(self, path_value=PathValue(), database=Parameter("network", default=""), scantime=Parameter("scan", default=""), info=Parameter("info", default="")):
		if path_value == 'networks':
			ext = [ os.path.splitext(f) for f in os.listdir(Storage.dbpath) ]
			ext = [ f[0] for f in ext if len(f[1]) > 0 and f[1] == '.sqlite' ]
			return { 'networks': ext }

		elif path_value == 'scans':
			storage = Storage(database, 0)
			return { 'scans': self.getScanFromNetwork(storage) }

		elif path_value == 'network':
			storage = Storage(database, 0)
			scan = storage.getLastScanId() if scantime == '' else int(scantime)
			return { 'hosts': self.getHostsFromScan(storage, scan) }

		elif path_value == 'info':
			storage = Storage(database, 0)
			scan = storage.getLastScanId() if scantime == '' else int(scantime)
			return { 'info': self.getScanInfoFromHosts(storage, scan, info.split(';')) }

	@request_map('/export/*', method='GET')
	def export_handler(self, database=PathValue(), export_type=Parameter("type", default=""), scantime=Parameter("scan", default="")):
		storage = Storage(database, 0)
		scan = storage.getLastScanId() if scantime == '' else int(scantime)

		if export_type == 'csv':
			return 200, Headers({'Content-Type':'text/csv; encoding=utf-8'}), self.getCsvExport(storage, scan)
		elif export_type == 'pdf':
			return 200, Headers({'Content-Type':'application/pdf; encoding=utf-8'}), self.getPdfExport(storage, scan)

	def getScanFromNetwork(self, storage):
		return storage.getScans()

	def getHostsFromScan(self, storage, scan):
		graph = Graph()
		return graph.buildHosts(storage, scan)

	def getScanInfoFromHosts(self, storage, scan, hosts):
		details = HostDetail(None)
		return details.buildInfo(storage, scan, hosts)

	def getCsvExport(self, storage, scan):
		csv = CsvExport()
		return csv.export(storage, scan)

	def getPdfExport(self, storage, scan):
		graph = Graph()
		return graph.export(storage, scan)


if __name__ == '__main__':
	server.scan("", r".*controller.*")
	server.start()
