import sqlite3

class Storage:
	def __init__(self, name):
		self.db = sqlite3.connect('%s.sqlite' % name)

	def __del__(self):
		self.db.commit()
		self.db.close()

	def prepare(self):
		self.db.execute('''CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY,
			ip NVARCHAR(40) DEFAULT "",
			mac NVARCHAR(20) DEFAULT "",
			vendor NVARCHAR(40) DEFAULT "",
			os NVARCHAR(100) DEFAULT "",
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			comment TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS routing (
			left INTEGER,
			right INTEGER,
			comment TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS ports (
			host INTEGER,
			port INTEGER DEFAULT 0,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			service NVARCHAR(100) DEFAULT "",
			comment TEXT DEFAULT ""
			)''')
		self.db.execute('''CREATE TABLE IF NOT EXISTS cves (
			port INTEGER,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			cve NVARCHAR(20) DEFAULT "",
			link NVARCHAR(200) DEFAULT "",
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

	def get(self, table, fields=[ '*' ], select = []):
		where = ''
		data = tuple()

		for exp in select:
			if (len(where)):
				where += ' ' + exp[2] + ' '
			where += exp[0]
			data += ( exp[1] , )
		cur = self.db.cursor()
		cur.execute('SELECT %s FROM %s %s' % ( ','.join(fields), table, 'WHERE ' + ''.join(where) if len(where) else '' ), data)
		return cur.fetchall()

