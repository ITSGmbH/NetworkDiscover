
CREATE TABLE IF NOT EXISTS scans (
	scan INTEGER DEFAULT 0,
	start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
	end_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scans_scan ON scans(scan);

CREATE TABLE IF NOT EXISTS log (
	log_time INTEGER DEFAULT CURRENT_TIMESTAMP,
	scan INTEGER DEFAULT 0,
	severity NVARCHAR(10) DEFAULT "info",
	origin NVARCHAR(15),
	log TEXT DEFAULT ""
);
CREATE INDEX idx_log_time ON log(log_time);
CREATE INDEX idx_log_scan ON log(scan);

CREATE TABLE IF NOT EXISTS hosts (
	id INTEGER PRIMARY KEY,
	ip NVARCHAR(40) DEFAULT "",
	ignore INTEGER DEFAULT 0,
	comment TEXT DEFAULT ""
);

CREATE INDEX idx_hosts_id ON hosts(id);
CREATE INDEX idx_hosts_ip ON hosts(ip);

CREATE TABLE IF NOT EXISTS hosts_history (
	id INTEGER PRIMARY KEY,
	host_id INTEGER NOT NULL,
	os NVARCHAR(100) DEFAULT "?",
	scan INTEGER DEFAULT 0
);

CREATE INDEX idx_hosts_hist_id ON hosts_history(id);
CREATE INDEX idx_hosts_hist_host_id ON hosts_history(host_id);
CREATE INDEX idx_hosts_hist_scan ON hosts_history(scan);

CREATE TABLE IF NOT EXISTS routing (
	scan INTEGER,
	left INTEGER,
	right INTEGER,
	comment TEXT DEFAULT ""
);

CREATE INDEX idx_routing_scan ON routing(scan);
CREATE INDEX idx_routing_left ON routing(left);
CREATE INDEX idx_routing_right ON routing(right);

CREATE TABLE IF NOT EXISTS ports (
	host_history_id INTEGER,
	port INTEGER DEFAULT 0,
	protocol NVARCHAR(5) DEFAULT "",
	state NVARCHAR(10) DEFAULT "",
	service NVARCHAR(100) DEFAULT "",
	product NVARCHAR(100) DEFAULT "",
	comment TEXT DEFAULT ""
);

CREATE INDEX idx_ports_host_hist_id ON ports(host_history_id);

CREATE TABLE IF NOT EXISTS cves (
	host_history_id INTEGER,
	port_id INTEGER,
	type NVARCHAR(20) DEFAULT "",
	type_id NVARCHAR(20) DEFAULT "",
	cvss DECIMAL(8,2) DEFAULT 0,
	is_exploit NVARCHAR(5) DEFAULT "false",
	scan INTEGER DEFAULT 0,
	comment TEXT DEFAULT ""
);

CREATE INDEX idx_cve_host_history_id ON cves(host_history_id);
CREATE INDEX idx_cve_port_id ON cves(port_id);
CREATE INDEX idx_cve_scan ON cves(scan);
