
pub struct Csv { }

impl Csv {

	/// Exports the given Scan and Network as a CSV
	///
	/// The Fields are separated by Semicolones (;),
	/// Lines are separated by a linefeed (\n)
	///
	/// # Arguments
	///
	/// * `db` - Mutable Reference to the Database connection
	/// * `network` - Network Identification to export
	/// * `scan` - Scan-ID to export
	///
	/// # Result
	///
	/// The CSV as a string
	pub fn export(db: &mut sqlite::Database, network: std::string::String, scan: i64) -> std::string::String {
		let header = "ID;IP;Network;Parent;OS;Ports".to_string();
		let hosts = db::Host::list_from_network(db, &network, &scan);
		hosts.iter()
			.map(|host| {
				let gw = db::Host::get_gateway(db, &host.hist_id, &scan).map_or_else(|| "0.0.0.0".to_string(), |host| host.ip);
				let ports = db::Port::load(db, &host.hist_id).iter()
					.map(|port| port.protocol.to_string() + "/" + &port.port.to_string())
					.reduce(|acc: String, proto: String| acc + "," + &proto )
					.unwrap_or("".to_string());

				host.id.to_string() + ";" + &host.ip + ";" + &host.network + ";" + &gw + ";" + &host.os + ";" + &ports
			})
			.fold(header, |acc: String, line: String| {
				acc + "\n" + &line
			})
			.to_string()
	}
}
