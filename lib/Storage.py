import sqlite3
import os
from datetime import datetime

class Storage:
	dbpath = 'db'

	def __init__(self, name, scan):
		if not os.path.isdir(self.dbpath):
			os.mkdir(self.dbpath)
		self.name = name
		self.scan = scan
		self.db = sqlite3.connect('file:' + self.dbpath + '/%s.sqlite%s' % (name, '?mode=ro' if scan <= 0 else ''), uri=True)

	def __del__(self):
		self.db.commit()
		self.db.close()

	def prepare(self):
		self.db.execute('''CREATE TABLE IF NOT EXISTS scans (
			scan INTEGER DEFAULT 0,
			start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
			end_time DATETIME DEFAULT CURRENT_TIMESTAMP
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS log (
			log_time INTEGER DEFAULT CURRENT_TIMESTAMP,
			scan INTEGER DEFAULT 0,
			severity VNARCHAR(10) DEFAULT "info",
			origin NVARCHAR(15),
			log TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY,
			ip NVARCHAR(40) DEFAULT "",
			scan INTEGER DEFAULT 0,
			ignore INTEGER DEFAULT 0,
			comment TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS hosts_history (
			id INTEGER PRIMARY KEY,
			host_id INTEGER NOT NULL,
			os NVARCHAR(100) DEFAULT "?",
			scan INTEGER DEFAULT 0
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS routing (
			left INTEGER,
			right INTEGER,
			comment TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS ports (
			host_history_id INTEGER,
			port INTEGER DEFAULT 0,
			protocol NVARCHAR(5) DEFAULT "",
			state NVARCHAR(10) DEFAULT "",
			service NVARCHAR(100) DEFAULT "",
			product NVARCHAR(100) DEFAULT "",
			scan INTEGER DEFAULT 0,
			comment TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS cves (
			port_id INTEGER,
			type NVARCHAR(20) DEFAULT "",
			type_id NVARCHAR(20) DEFAULT "",
			cvss DECIMAL(8,2) DEFAULT 0,
			is_exploit NVARCHAR(5) DEFAULT "false",
			scan INTEGER DEFAULT 0,
			comment TEXT DEFAULT ""
			)''')

	def insert(self, table, values):
		fields = []
		data = []
		for field in values.items():
			fields.append( field[0] )
			data.append( field[1] )
		placeholder = ','.join( [ '?' for x in range(0, len(values), 1) ] )
		fields = ','.join(fields)
		self.db.executemany('INSERT INTO %s (%s) VALUES(%s)' % (table, fields, placeholder) , [ tuple(data) ])

	def update(self, table, values, select = []):
		fields = []
		where = ''
		placeholder = []
		data = tuple()

		for val in values.items():
			if val[1] == 'CURRENT_TIMESTAMP':
				placeholder.append(val[0] + '=CURRENT_TIMESTAMP')
			else:
				placeholder.append(val[0] + '=?')
				data += ( val[1], )

		for exp in select:
			if len(exp) <= 2:
				exp += ('AND', )
			if len(where) > 0:
				where += ' ' + exp[2] + ' '
			where += exp[0]
			data += ( exp[1], )
		cur = self.db.cursor()
		cur.execute('UPDATE %s SET %s WHERE %s' % ( table, ','.join(placeholder), where ), data)
		cur.close()

	def get(self, table, fields=[ '*' ], select = []):
		where = ''
		data = tuple()

		for exp in select:
			if len(exp) == 1:
				exp += (None, )
			if len(exp) == 2:
				exp += ('AND', )
			if len(where) > 0:
				where += ' ' + exp[2] + ' '
			where += exp[0]
			if exp[1] != None:
				data += ( exp[1], )
		cur = self.db.cursor()
		cur.execute('SELECT %s FROM %s %s' % ( ','.join(fields), table, 'WHERE ' + ''.join(where) if len(where) else '' ), data)
		return cur.fetchall()

	def startScan(self):
		self.insert('scans', { 'scan': self.scan, 'end_time': '0' })

	def endScan(self):
		self.update('scans', { 'end_time': 'CURRENT_TIMESTAMP' }, [ ('scan=?', self.scan) ])

	def getLastScanId(self):
		result = self.get('scans', ['MAX(scan)'])
		return result[0][0] if result is not None else 0

	def getScans(self):
		return [ { 'scan': scan[0], 'start': scan[1], 'end': scan[2] } for scan in self.get('scans', ['scan', 'start_time', 'end_time'], []) ]
