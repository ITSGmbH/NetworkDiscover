
CREATE TABLE IF NOT EXISTS script_scan (
	id INTEGER PRIMARY KEY,
	scan INTEGER DEFAULT 0,
	hist_id INTEGER DEFAULT 0,
	script_id NVARCHAR(254) DEFAULT ''
);
CREATE INDEX idx_script_scan ON script_scan(scan);
CREATE INDEX idx_script_host ON script_scan(hist_id);


CREATE TABLE IF NOT EXISTS script_result (
	script_id INTEGER DEFAULT 0,
	key NVARCHAR(254) DEFAULT "",
	value TEXT DEFAULT ""
);
CREATE INDEX idx_script_id ON script_result(script_id);
