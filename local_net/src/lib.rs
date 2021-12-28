

#[cfg(not(test))]
pub mod local_net {
	use log::{info, debug};
	use std::process::Command;
	use std::net::IpAddr;
	
	pub struct LocalNet {
		ipv4: Option<IpAddr>,
		ipv6: Option<IpAddr>,
	}
	
	pub fn discover(device: &Option<String>) {
		info!("LocalNet discovery: Starting");
		
		discover_host_information(device);
		
		info!("LocalNet discovery: End");
	}
	
	fn discover_host_information(device: &Option<String>) {
		let mut cmd = Command::new("ip");
		cmd.arg("address")
			.arg("show");
		
		if device.is_some() {
			cmd.arg(device.as_ref().unwrap());
		}
		
		let output = cmd.output();
		if output.is_ok() {
			let lines = String::from_utf8(output.unwrap().stdout).unwrap();
			for line in lines.lines() {
				let parts = line.trim().split_whitespace();
				
				
				info!("{}", line);
			}
			info!("cmd: {:?}", lines);
		}
		
	}
	
}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
