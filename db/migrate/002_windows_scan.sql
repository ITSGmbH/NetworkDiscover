
CREATE TABLE IF NOT EXISTS windows (
	id INTEGER PRIMARY KEY,
	scan INTEGER DEFAULT 0,
	hist_id INTEGER DEFAULT 0
);
CREATE INDEX idx_windows_scan ON windows(scan);
CREATE INDEX idx_windows_host ON windows(hist_id);


CREATE TABLE IF NOT EXISTS windows_info (
	id INTEGER PRIMARY KEY,
	windows_id INTEGER DEFAULT 0,
	native_lan_manager NVARCHAR(254) DEFAULT "",
	native_os NVARCHAR(254) DEFAULT "",
	os_name NVARCHAR(254) DEFAULT "",
	os_build NVARCHAR(20) DEFAULT "",
	os_release NVARCHAR(20) DEFAULT "",
	os_version NVARCHAR(20) DEFAULT "",
	platform NVARCHAR(10) DEFAULT "",
	server_type NVARCHAR(10) DEFAULT "",
	server_string NVARCHAR(254) DEFAULT ""
);
CREATE INDEX idx_win_info_id ON windows_info(windows_id);


CREATE TABLE IF NOT EXISTS windows_domain (
	id INTEGER PRIMARY KEY,
	windows_id INTEGER DEFAULT 0,
	domain NVARCHAR(254) DEFAULT "",
	fqdn NVARCHAR(254) DEFAULT "",
	dns_domain NVARCHAR(254) DEFAULT "",
	derived_domain NVARCHAR(254) DEFAULT "",
	derived_membership NVARCHAR(254) DEFAULT "",
	netbios_name NVARCHAR(254) DEFAULT "",
	netbios_domain NVARCHAR(254) DEFAULT ""
);
CREATE INDEX idx_win_domain_id ON windows_domain(windows_id);


CREATE TABLE IF NOT EXISTS windows_printer (
	id INTEGER PRIMARY KEY,
	windows_id INTEGER DEFAULT 0,
	uri NVARCHAR(254) DEFAULT "",
	flags NVARCHAR(10) DEFAULT "",
	description TEXT DEFAULT "",
	comment TEXT DEFAULT ""
);
CREATE INDEX idx_win_printer_id ON windows_printer(windows_id);


CREATE TABLE IF NOT EXISTS windows_share (
	id INTEGER PRIMARY KEY,
	windows_id INTEGER DEFAULT 0,
	name NVARCHAR(254) DEFAULT "",
	type NVARCHAR(100) DEFAULT "",
	comment TEXT DEFAULT ""
);
CREATE INDEX idx_win_share_id ON windows_share(windows_id);


CREATE TABLE IF NOT EXISTS windows_access (
	id INTEGER PRIMARY KEY,
	share_id INTEGER DEFAULT 0,
	name NVARCHAR(100) DEFAULT "",
	value NVARCHAR(100) DEFAULT ""
);
CREATE INDEX idx_win_access_id ON windows_access(share_id);
