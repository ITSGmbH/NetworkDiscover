use std::string::String;
use log::error;
use chrono::prelude::Local;
use std::collections::{BTreeMap};
use std::fs::File;
use std::io::prelude::*;
// use chrono::{DateTime};
use printpdf::{
	pdf_document::PdfDocumentReference, Mm,
	PdfDocument, IndirectFontRef, PdfPageIndex, PdfLayerIndex, PdfLayerReference,
	svg::Svg, svg::SvgTransform,
	Rgb, Color, line::Line, point::Point
};

pub struct Pdf<'a> {
	db: &'a mut sqlite::Database,
	network: &'a str,
	scan: &'a i64,
	font_regular: IndirectFontRef,
	font_bold: IndirectFontRef,
	header_space: f64,
	header_underline_offset: f64,
	header_font_size: f64,
	font_size: f64,
	line_height: f64,
	page_top: f64,
	pages: Vec<(PdfPageIndex, PdfLayerIndex)>
}

/*
#[derive(Debug)]
struct Node {
	id: i64,
	label: String,
	os: String,
	parent: i64,
	edges: Vec<i64>,
	level: i64,
	pos_x: f64,
	pos_y: f64,
}
*/

/*
impl Default for Node {
	fn default() -> Self {
		Node {
			id: 0, level: 0,
			label: String::from(""), os: String::from(""),
			parent: 0, edges: vec![],
			pos_x: 0.0, pos_y: 0.0,
		}
	}
}
*/

impl Pdf<'_> {

	/// Exports the given Scan and Network as a PDF
	///
	/// # Arguments
	///
	/// * `db` - Mutable Reference to the Database connection
	/// * `network` - Network Identification to export
	/// * `scan` - Scan-ID to export
	///
	/// # Result
	///
	/// The PDF as a binary string which can be saved to a file or presented as a stream to a browser
	pub fn export(db: &mut sqlite::Database, network: String, scan: i64) -> String {
		let (doc, page, layer) = PdfDocument::new("ITScan", Mm(210.0), Mm(297.0), "Seite 1");
		let font_regular_reader = File::open("static/assets/EuclidCircularB-Light.ttf");
		let font_bold_reader = File::open("static/assets/EuclidCircularB-Black.ttf");

		let mut pdf = Pdf {
			db,
			network: &network,
			scan: &scan,
			font_regular: match font_regular_reader {
				Ok(font) => doc.add_external_font(font).unwrap(),
				Err(_why) => doc.add_builtin_font(printpdf::BuiltinFont::Helvetica).unwrap(),
			},
			font_bold: match font_bold_reader {
				Ok(font) => doc.add_external_font(font).unwrap(),
				Err(_why) => doc.add_builtin_font(printpdf::BuiltinFont::HelveticaBold).unwrap(),
			},
			header_space: 16.0,
			header_underline_offset: 2.0,
			header_font_size: 15.0,
			font_size: 10.5,
			line_height: 6.0,
			page_top: 266.0,
			pages: vec![]
		};

		pdf.create_title_page(&doc, &page, &layer);

		// pdf.add_network(&doc);
		pdf.add_hosts(&doc);

		// Nachdem alle Seiten hinzugefügt wurden, füge die Seitennummerierung hinzu
		let total_pages = pdf.pages.len();

		for (i, (page, layer)) in pdf.pages.iter().enumerate() {
			let current_layer = doc.get_page(*page).get_layer(*layer);
			let text = format!("Seite {} von {}", i + 1, total_pages);
			current_layer.use_text(text,8.0, Mm(175.0), Mm(6.0), &pdf.font_regular);
		}

		let bin_pdf = doc.save_to_bytes().unwrap();
		String::from_utf8_lossy(&bin_pdf).to_string()
	}

	/// Build and add the Title-Page for the PDF
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `page_index` - Page Index to add the title page onto
	/// * `layer_index` - Layer index on the page to add the header onto
	fn create_title_page(&mut self, doc: &PdfDocumentReference, page_index: &PdfPageIndex, layer_index: &PdfLayerIndex) {
		let layer = doc.get_page(*page_index).get_layer(*layer_index);

		match Self::get_svg("static/assets/logo.svg") {
			None => {}
			Some(svg) => {
				svg.add_to_layer(&layer, SvgTransform {
					translate_x: Some(Mm(17.25).into()),
					translate_y: Some(Mm(280.0).into()),
					scale_x: Some(1.0),
					scale_y: Some(1.0),
					.. Default::default()
				});
			},
		}

		/*
		IT-S GmbH
		Industriestrasse 17
		9552 Bronschhofen
		+41 71 966 63 63
		info@it-s.ch
		it-s.ch
		Zürichbergstrasse 98
		8044 Zürich
		Birsmatt 6
		4147 Aesch BL
		*/

		layer.use_text("IT-S GmbH".to_string(), 8.0, Mm(175.0), Mm(287.0), &self.font_bold);
		layer.use_text("Industriestrasse 17".to_string(), 8.0, Mm(175.0), Mm(283.0), &self.font_regular);
		layer.use_text("9552 Bronschhofen".to_string(), 8.0, Mm(175.0), Mm(279.5), &self.font_regular);
		layer.use_text("+41 71 966 63 63".to_string(), 8.0, Mm(175.0), Mm(276.0), &self.font_regular);
		layer.use_text("info@it-s.ch".to_string(), 8.0, Mm(175.0), Mm(272.5), &self.font_regular);
		layer.use_text("www.it-s.ch".to_string(), 8.0, Mm(175.0), Mm(269.0), &self.font_regular);

		layer.use_text("Zürichbergstrasse 98".to_string(), 8.0, Mm(175.0), Mm(263.0), &self.font_regular);
		layer.use_text("8044 Zürich".to_string(), 8.0, Mm(175.0), Mm(259.5), &self.font_regular);

		layer.use_text("Birsmatt 6".to_string(), 8.0, Mm(175.0), Mm(254.5), &self.font_regular);
		layer.use_text("4147 Aesch BL".to_string(), 8.0, Mm(175.0), Mm(251.0), &self.font_regular);

		// Set the text color
		let text_color = Color::Rgb(Rgb::new(0.0627,0.0235,0.6235, None)); // RGB color: Green
		layer.set_fill_color(text_color);

		layer.use_text("ITScan".to_string(), 45.0, Mm(25.0), Mm(160.0), &self.font_bold);

		let text_color = Color::Rgb(Rgb::new(0.0,0.0,0.0, None)); // RGB color: Green
		layer.set_fill_color(text_color);

		// layer.use_text("Scan: ".to_string() + &self.scan.to_string(), 12.0, Mm(25.0), Mm(150.0), &self.font_regular);
		// doc.get_page(&self, page_index)

		let scan_date = match db::Scan::load(self.db, self.scan) {
			// Some(scan) => DateTime::parse_from_str("%d.%m.%Y %H:%M:%S", scan.start_time.to_string()),
			Some(scan) => scan.start_time.and_local_timezone(Local::now().timezone()).unwrap().format("%d.%m.%Y %H:%M:%S").to_string(),
			None => "Unknown".to_string()
		};
		layer.use_text("Datum: ".to_string() + &scan_date, 12.0, Mm(25.0), Mm(150.0), &self.font_bold);

		// Footer
		let text_color = Color::Rgb(Rgb::new(0.0627,0.0235,0.6235, None)); // RGB color: Green
		layer.set_fill_color(text_color);
		layer.use_text("IT ist".to_string(), 34.85, Mm(25.0), Mm(6.0), &self.font_bold);
		let text_color = Color::Rgb(Rgb::new(0.0,0.0,0.0, None)); // RGB color: Green
		layer.set_fill_color(text_color);
		layer.use_text("sicher.".to_string(), 34.85, Mm(57.0), Mm(6.0), &self.font_regular);
	}

	/// Loads a file as text and tries to parse it as SVG
	///
	/// # Arguments:
	///
	/// * `path` - SVG-File to read and parse
	///
	/// # Result
	///
	/// An SVG object
	fn get_svg(path: &str) -> Option<Svg> {
		let mut file = match File::open(path) {
			Err(why) => { error!("Loading SVG {}: {}", path, why); return None; },
			Ok(file) => file,
		};

		let mut svg = String::new();
		match file.read_to_string(&mut svg) {
			Err(why) => { error!("Reading SVG {}: {}", path, why); return None; },
			Ok(_) => { },
		};

		match Svg::parse(&svg) {
			Err(why) => { error!("Parsing SVG {}: {}", path, why); None },
			Ok(svg) => Some(svg),
		}
	}

	/// Create a page with the whole network visualized
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document to add all hosts
	/*
	fn add_network(&mut self, doc: &PdfDocumentReference) {
		let mut nodes: HashMap<i64, Node> = HashMap::new();
		db::Host::list_from_network(self.db, self.network, self.scan)
			.iter()
			.map(|host| Node {
				id: host.hist_id,
				label: String::from(&host.ip),
				os: String::from(&host.os),
				.. Default::default()
			})
			.for_each(|mut node| {
				node.parent = db::Routing::from_host(self.db, &node.id, self.scan)
					.iter()
					.map(|route| route.right)
					.reduce(|a, _| a)
					.unwrap_or(0);
				node.edges = db::Routing::to_host(self.db, &node.id, self.scan)
					.iter()
					.map(|route| route.left)
					.collect();
				nodes.insert(node.id, node);
			});

		// Starting node is the first one with no parent
		// TODO: Multiple starting nodes cannot be handled at the moment
		let mut start_node: i64 = 0;
		for (key, node) in &nodes {
			if node.parent == 0 {
				start_node = i64::from(*key);
				break;
			}
		}

		// Calculate the distance from the starting node for each individual node
		Self::build_node_distances(start_node, 0, &mut nodes);

		// Calculate the nodes position
		let grid_h = 13.0;
		let grid_w = 30.0;
		let center_h = self.min_bottom + (self.max_bottom - self.min_bottom + grid_h) / 2.0;
		let mut next_level_pos = Self::init_start_pos_per_level(&nodes, grid_h, center_h);
		for (_, node) in &mut nodes {
			node.pos_x = self.min_left + (grid_w * (node.level as f64));
			node.pos_y = f64::from(*(next_level_pos.get(&node.level).unwrap_or(&0.0)));
			next_level_pos.insert(node.level, node.pos_y + grid_h);
		}

		// Finally print the nodes and the connection lines
		let offset_x_parent = 5.0;
		let offset_x_node = 1.8;
		let offset_y_parent = 2.2;
		let offset_y_node = 2.2;
		let layer = self.add_page(doc, "Network");
		layer.set_outline_color( Color::Rgb(Rgb::new(0.8, 0.8, 0.8, None)) );
		layer.set_fill_color( Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)) );
		layer.set_outline_thickness(0.2);
		for (_, node) in &nodes {
			match nodes.get(&node.parent) {
				Some(parent) => self.draw_line(&(parent.pos_x + offset_x_parent), &(parent.pos_y + offset_y_parent), &(node.pos_x - offset_x_node), &(node.pos_y + offset_y_node), &layer),
				_ => {}
			}
			self.add_host_with_label(&layer, &node.pos_x, &node.pos_y, &node.label, &node.os);
		}
	}
	*/

	/// Calculates the starting position from bottom in contrast to the given center
	///
	/// # Arguments
	///
	/// * `nodes` - All the nodes with already calculated levels
	/// * `distance` - horizontal distance between the nodes
	/// * `center` - the center around which the nodes should be placed equally
	///
	/// # Result
	///
	/// A HashMap with the key corresponds to the level and the value as the starting position
	/*
	fn init_start_pos_per_level(nodes: &HashMap<i64, Node>, distance: f64, center: f64) -> HashMap<i64, f64> {
		let mut start_pos: HashMap<i64, f64> = HashMap::new();
		let nodes_per_level = Self::get_nodes_per_level(&nodes);
		for (k, v) in nodes_per_level {
			let pos = center - ((v as f64) * distance / 2.0);
			start_pos.insert(k, pos);
		}
		start_pos
	}
	*/

	/// Returns the number of nodes per level.
	///
	/// # Arguments
	///
	/// * `nodes` - Reference to the Nodes HashMap which has already calculated levels
	///
	/// # Result
	///
	/// A HashMap where the key is the level and the value is the number of nodes on that level
	/*
	fn get_nodes_per_level(nodes: &HashMap<i64, Node>) -> HashMap<i64, i64> {
		let mut nums: HashMap<i64, i64> = HashMap::new();
		for (_, node) in nodes {
			let mut num = *nums.get(&node.level).unwrap_or(&0);
			num = num + 1;
			nums.insert(node.level, i64::from(num));
		}
		nums
	}
	*/

	/// Calculates the distances for each node compared to the first node.
	/// The distance is changed on the node referece.
	///
	/// # Arguments
	///
	/// * `current` - The node key to process the edges
	/// * `distance` - Distance for the given node
	/// * `nodes` - HashMap of all nodes
	/*
	fn build_node_distances(current: i64, distance: i64, nodes: &mut HashMap<i64, Node>) {
		let mut edges: Vec<i64> = vec![];
		match nodes.get_mut(&current) {
			Some(n) => {
				n.level = i64::from(distance);
				edges.append(&mut n.edges);
			}
			_ => {}
		}
		let max = 20;
		for (k, next) in edges.into_iter().enumerate() {
			Self::build_node_distances(next, distance + (k as i64 / max) + 1, nodes);
		}
	}
	*/

	/// Add a host icon with a label below it
	///
	/// # Arguments
	///
	/// * `layer` - Layer to add the icon to
	/// * `left` - Position from the left
	/// * `bottom` - Position from the bottom
	/// * `label` - Label to show below
	/// * `os` - Operating System to find the correct icon
	/*
	fn add_host_with_label(&self, layer: &PdfLayerReference, left: &f64, bottom: &f64, label: &str, os: &str) {
		self.add_host_icon(&layer, os, left, bottom, &3.0, &3.0);
		let center = left + 1.7 - (7.0 * label.len() as f64 * 0.09); // Based on precise guessing
		layer.use_text(label, 7.0, Mm(center), Mm(bottom - 2.6), &self.font_regular);
	}
	*/

	/// Add all hosts from the given Scan to the PDF
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document to add all hosts
	fn add_hosts(&mut self, doc: &PdfDocumentReference) {
		db::Host::list_from_network(self.db, self.network, self.scan)
			.iter()
			.for_each(|host| self.add_host_page(&doc, &host));
	}

	/// Adds a new page and returns the layer to print all the elements on.
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document to add all hosts
	/// * `title` - Title/name of the page
	///
	/// # Result
	///
	/// The Layer to add new elements onto
	fn add_page(&mut self, doc: &PdfDocumentReference, title: &str) -> PdfLayerReference {
		let (page_index, layer_index) = doc.add_page(Mm(210.0), Mm(297.0), String::from(title));
		self.pages.push((page_index, layer_index));
		self.add_header_and_footer(doc, &page_index, &layer_index);

		let layer = doc.get_page(page_index).get_layer(layer_index);
		layer.set_outline_color( Color::Rgb(Rgb::new(0.8, 0.8, 0.8, None)) );
		layer.set_fill_color( Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)) );
		layer.set_outline_thickness(0.2);

		return layer
	}

	/// Adds one or more pages for a Host to the PDF
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `host` - Reference to the Host
	fn add_host_page(&mut self, doc: &PdfDocumentReference, host: &db::Host) {
		let title = "Host ".to_string() + &host.ip;
		let mut layer = self.add_page(doc, &title);

		let mut start_top = self.add_hosts_header(&layer, host, self.page_top);
		start_top -= self.header_space;

		(start_top, layer) = self.add_services_part(doc, layer.clone(), &title, start_top, host);
		(start_top, layer) = self.add_windows_part(doc, layer.clone(), &title, start_top, host);
		(_, _) = self.add_vulnerabilities_part(doc, layer.clone(), &title, start_top, host);
	}

	/// Add all services from the given host to the page
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `page` - Current Layer/Page to draw on
	/// * `page_title` - Title for any further page
	/// * `top` - Where to start vertically
	/// * `host` - Host to show the services from
	///
	/// # Returns
	///
	/// A Tuple tith the vertical position for the next part and the PDF Layer-Reference
	fn add_services_part(&mut self, doc: &PdfDocumentReference, mut page: PdfLayerReference, page_title: &str, top: f64, host: &db::Host) -> (f64, PdfLayerReference) {
		let mut even_line = true;
		let mut start_top = top;
		let ports = db::Port::load(self.db, &host.hist_id);
		if ports.len() > 0 {
			(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top, true);
			page.use_text("Services:".to_string(), self.header_font_size, Mm(25.0), Mm(start_top), &self.font_bold);
			self.draw_line(&15.0, &(start_top - self.header_underline_offset), &200.0, &(start_top - self.header_underline_offset), &page);
			start_top -= self.line_height / 2.0;

			ports.iter()
				.for_each(|port| {
					(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top - self.line_height, false);
					even_line = self.draw_highlight_line(even_line, &start_top, &self.line_height, &20.0, &200.0, &page);

					page.use_text(port.port.to_string() + "/" + &port.protocol, self.font_size, Mm(25.0), Mm(start_top), &self.font_regular);
					page.use_text(String::from(&port.service), self.font_size, Mm(50.0), Mm(start_top), &self.font_regular);
					page.use_text(String::from(&port.product), self.font_size, Mm(85.0), Mm(start_top), &self.font_regular);
			});
			start_top -= self.header_space;
		}
		(start_top, page)
	}

	/// Add all windows scan information from the given host to the page
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `page` - Current Layer/Page to draw on
	/// * `page_title` - Title for any further page
	/// * `top` - Where to start vertically
	/// * `host` - Host to show the services from
	///
	/// # Returns
	///
	/// A Tuple with the vertical position for the next part and the PDF Layer-Reference
	fn add_windows_part(&mut self, doc: &PdfDocumentReference, mut page: PdfLayerReference, page_title: &str, top: f64, host: &db::Host) -> (f64, PdfLayerReference) {
		let mut start_top = top;

		if let Some(win) = db::Windows::load(self.db, &host.hist_id) {
			let mut win_data: Vec<(&str, String)> = vec![];
			if let Some(info) = db::WindowsInfo::load(self.db, &win.id) {
					if !info.native_lan_manager.is_empty() { win_data.push((&"Native LAN Manager", info.native_lan_manager)); }
					if !info.native_os.is_empty() { win_data.push((&"Native OS", info.native_os)); }
					if !info.os_name.is_empty() { win_data.push((&"OS name", info.os_name)); }
					if !info.os_build.is_empty() { win_data.push((&"OS Build", info.os_build)); }
					if !info.os_release.is_empty() { win_data.push((&"OS Release", info.os_release)); }
					if !info.os_version.is_empty() { win_data.push((&"OS Version", info.os_version)); }
					if !info.platform.is_empty() { win_data.push((&"Platform", info.platform)); }
					if !info.server_type.is_empty() { win_data.push((&"Server Type", info.server_type)); }
					if !info.server_string.is_empty() { win_data.push((&"Server String", info.server_string)); }
			}
			if let Some(domain) = db::WindowsDomain::load(self.db, &win.id) {
					if !domain.domain.is_empty() { win_data.push((&"Domain", domain.domain)); }
					if !domain.dns_domain.is_empty() { win_data.push((&"DNS Domain", domain.dns_domain)); }
					if !domain.derived_domain.is_empty() { win_data.push((&"Derived Domain", domain.derived_domain)); }
					if !domain.derived_membership.is_empty() { win_data.push((&"Derived Membership", domain.derived_membership)); }
					if !domain.fqdn.is_empty() { win_data.push((&"FQDN", domain.fqdn)); }
					if !domain.netbios_name.is_empty() { win_data.push((&"NetBIOS Name", domain.netbios_name)); }
					if !domain.netbios_domain.is_empty() { win_data.push((&"NetBIOS Domain", domain.netbios_domain)); }
			}
			if win_data.len() > 0 {
				(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top, true);
				page.use_text("Windows Information:".to_string(), self.header_font_size, Mm(25.0), Mm(start_top), &self.font_bold);
				self.draw_line(&15.0, &(start_top - self.header_underline_offset), &200.0, &(start_top - self.header_underline_offset), &page);
				start_top -= self.line_height / 2.0;

				let mut even_line = true;
				win_data.iter()
					.for_each(|(key, value)| {
						(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top - self.line_height, false);
						even_line = self.draw_highlight_line(even_line, &start_top, &self.line_height, &20.0, &200.0, &page);

						page.use_text(String::from(*key), self.font_size, Mm(25.0), Mm(start_top), &self.font_regular);
						page.use_text(value, self.font_size, Mm(85.0), Mm(start_top), &self.font_regular);
				});
				start_top -= self.header_space;
			}

			let shares = db::WindowsShare::load(self.db, &win.id);
			if shares.len() > 0 {
				(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top, true);
				page.use_text("Windows Shares:".to_string(), self.header_font_size, Mm(25.0), Mm(start_top), &self.font_bold);
				self.draw_line(&15.0, &(start_top - self.header_underline_offset), &200.0, &(start_top - self.header_underline_offset), &page);
				start_top -= self.line_height / 2.0;

				let mut even_line = true;
				shares.iter()
					.for_each(|share| {
						(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top - self.line_height, false);
						even_line = self.draw_highlight_line(even_line, &start_top, &self.line_height, &20.0, &200.0, &page);

						page.use_text(String::from(&share.name), self.font_size, Mm(25.0), Mm(start_top), &self.font_regular);
						page.use_text(String::from(&share.share_type), self.font_size, Mm(50.0), Mm(start_top), &self.font_regular);
						page.use_text(String::from(&share.comment), self.font_size, Mm(85.0), Mm(start_top), &self.font_regular);
				});
				start_top -= self.header_space;
			}

			let printers = db::WindowsPrinter::load(self.db, &win.id);
			if printers.len() > 0 {
				(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top, true);
				page.use_text("Shared Printers:".to_string(), self.header_font_size, Mm(25.0), Mm(start_top), &self.font_bold);
				self.draw_line(&15.0, &(start_top - self.header_underline_offset), &200.0, &(start_top - self.header_underline_offset), &page);
				start_top -= self.line_height / 2.0;

				let mut even_line = true;
				printers.iter()
					.for_each(|printer| {
						// Comments will be shown below the URI
						let (line_height, line_offset) = if printer.description.is_empty() { (self.line_height, 0.0) } else { (2.0 * self.line_height, self.line_height) };

						(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top - line_height, false);
						even_line = self.draw_highlight_line(even_line, &start_top, &line_height, &20.0, &200.0, &page);

						page.use_text(String::from(&printer.uri), self.font_size, Mm(25.0), Mm(start_top + line_offset), &self.font_regular);
						page.use_text(String::from(&printer.comment), self.font_size, Mm(85.0), Mm(start_top + line_offset), &self.font_regular);
						if !printer.description.is_empty() {
							page.use_text(String::from(&printer.description), self.font_size, Mm(25.0), Mm(start_top), &self.font_regular);
						}
				});
				start_top -= self.header_space;
			}
		}
		(start_top, page)
	}

	/// Add all Vulnerabilities from the given Host
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `page` - Current Layer/Page to draw on
	/// * `page_title` - Title for any further page
	/// * `top` - Where to start vertically
	/// * `host` - Host to show the services from
	///
	/// # Returns
	///
	/// A Tuple with the vertical position for the next part and the PDF Layer-Reference
	fn add_vulnerabilities_part(&mut self, doc: &PdfDocumentReference, mut page: PdfLayerReference, page_title: &str, top: f64, host: &db::Host) -> (f64, PdfLayerReference) {
		let mut even_line = true;
		let mut start_top = top;
		let cves = db::Cve::from_host_hist(self.db, &host.hist_id);
		if cves.len() > 0 {
			(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top, true);
			page.use_text("Possible Vulnerabilities:".to_string(), self.header_font_size, Mm(25.0), Mm(start_top), &self.font_bold);
			self.draw_line(&15.0, &(start_top - self.header_underline_offset), &200.0, &(start_top - self.header_underline_offset), &page);
			start_top -= self.line_height * 1.8;

			let mut grouped: BTreeMap<String, Vec<&db::Cve>> = BTreeMap::new();
			cves.iter()
				.for_each(|cve| {
					let cves: &mut Vec<&db::Cve> = match grouped.get_mut(&cve.type_name) {
						Some(val) => val,
						None => {
							grouped.insert(String::from(&cve.type_name), Vec::new());
							grouped.get_mut(&cve.type_name).unwrap()
						}
					};
					cves.push(cve);
				});

			grouped.iter().for_each(|(group, cves)| {
				(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top, true);
				page.use_text(String::from(group).to_uppercase(), self.font_size, Mm(23.0), Mm(start_top), &self.font_bold);
				page.use_text(String::from("CVSS"), self.font_size, Mm(178.0), Mm(start_top), &self.font_bold);
				self.draw_line(&20.0, &(start_top - self.header_underline_offset), &200.0, &(start_top - self.header_underline_offset), &page);

				start_top -= 2.2;
				cves.iter().for_each(|cve| {
					(start_top, page) = self.add_new_page_if_needed(doc, page.clone(), &page_title, start_top - self.line_height, false);
					even_line = self.draw_highlight_line(even_line, &start_top, &self.line_height, &23.0, &200.0, &page);

					page.use_text(String::from(&cve.type_id), self.font_size, Mm(25.0), Mm(start_top), &self.font_regular);
					page.use_text(format!("{:.1}", cve.cvss), self.font_size, Mm( if cve.cvss >= 10.0 { 180.0 } else { 182.1 }), Mm(start_top), &self.font_regular);
				});
				start_top -= self.line_height * 1.8;
			});
		}
		(start_top, page)
	}

	/// Based on the current vertical position it is decided if a new page should be inserted.
	/// The Vertical position and a Reference to the PDF Page is returned.
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `page` - Current Layer/Page to draw on
	/// * `page_title` - Title for any further page
	/// * `top` - Where to start vertically
	/// * `header` - Check the space for a header
	///
	/// # Returns
	///
	/// A Tuple with the vertical position for the next part and the PDF Layer-Reference
	fn add_new_page_if_needed(&mut self, doc: &PdfDocumentReference, mut page: PdfLayerReference, page_title: &str, top: f64, header: bool) -> (f64, PdfLayerReference) {
		let mut start_top = top;
		let needed_space = if header { self.header_space + self.header_font_size + (self.line_height * 2.0) } else { self.header_space };
		if start_top < needed_space {
			page = self.add_page(doc, &page_title);
			start_top = self.page_top;
		}
		(start_top, page)
	}

	/// Adds a header and footer to the PDF Page
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `page_index` - Page Index to add a header and footer
	/// * `layer_index` - Layer index on the page to add the header and footer onto
	fn add_header_and_footer(&self, doc: &PdfDocumentReference, page_index: &PdfPageIndex, layer_index: &PdfLayerIndex) {
		let layer = doc.get_page(*page_index).get_layer(*layer_index);
		match Self::get_svg("static/assets/logo.svg") {
			None => {}
			Some(svg) => {
				svg.add_to_layer(&layer, SvgTransform {
					translate_x: Some(Mm(17.25).into()),
					translate_y: Some(Mm(280.0).into()),
					scale_x: Some(1.0),
					scale_y: Some(1.0),
					.. Default::default()
				});
			},
		}

		// Header
		layer.use_text("IT-S GmbH".to_string(), 8.0, Mm(175.0), Mm(287.0), &self.font_bold);
		layer.use_text("www.it-s.ch".to_string(), 8.0, Mm(175.0), Mm(284.0), &self.font_regular);

		// Footer
		let text_color = Color::Rgb(Rgb::new(0.0627,0.0235,0.6235, None)); // RGB color: Green
		layer.set_fill_color(text_color);
		layer.use_text("IT ist".to_string(), 34.85, Mm(25.0), Mm(6.0), &self.font_bold);
		let text_color = Color::Rgb(Rgb::new(0.0,0.0,0.0, None)); // RGB color: Green
		layer.set_fill_color(text_color);
		layer.use_text("sicher.".to_string(), 34.85, Mm(57.0), Mm(6.0), &self.font_regular);

		// layer.use_text(Local::now().format("%d.%m.%Y %H:%M:%S").to_string(), 10.0, Mm(167.0), Mm(6.0), &self.font_regular);
/*
		let header_line = Line {
			points: vec![ (Point::new(Mm(10.0), Mm(275.0)), false), (Point::new(Mm(200.0), Mm(275.0)), false) ],
			is_closed: false,
			has_fill: false,
			has_stroke: true,
			is_clipping_path: false,
		};
		let footer_line = Line {
			points: vec![ (Point::new(Mm(10.0), Mm(10.5)), false), (Point::new(Mm(200.0), Mm(10.5)), false) ],
			is_closed: false,
			has_fill: false,
			has_stroke: true,
			is_clipping_path: false,
		};

		let line_color = Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None));
		layer.set_outline_color(line_color);
		layer.set_outline_thickness(0.5);
		layer.add_shape(header_line);
		layer.add_shape(footer_line);
		*/
	}

	/// Prints a simple header on the given PDF-Layer with all needed information from the given host.
	///
	/// # Arguments
	///
	/// * `layer` - The PDFLayer to print the header on
	/// * `host` - Host struct to get all information from
	/// * `start_top` - Position from bottom where to start with the header
	///
	/// # Returns
	///
	/// The new position form bottom where the next text has to be oriented at
	fn add_hosts_header(&mut self, layer: &PdfLayerReference, host: &db::Host, start_top: f64) -> f64 {
		let mut start_top_fnc = start_top;

		let gw = db::Host::get_gateway(self.db, &host.hist_id, &self.scan).map_or_else(|| "0.0.0.0".to_string(), |host| host.ip);
		let first_emerge = db::Host::find_first_emerge(self.db, &host.ip).map_or(false, |h| h.id == host.hist_id);
		let last_emerge = db::Host::find_last_emerge(self.db, &host.ip).map_or(false, |h| h.id == host.hist_id);

		let pos_key = 50.0;
		let pos_val = 86.0;

		let mut netbios_name:String = "Unknown".to_string();
		if let Some(win) = db::Windows::load(self.db, &host.hist_id) {
			if let Some(domain) = db::WindowsDomain::load(self.db, &win.id) {
				netbios_name = domain.netbios_name.to_string();
			}
		}

		// Text
		start_top_fnc -= self.line_height;
		layer.use_text("Host: ".to_string(), self.font_size, Mm(pos_key), Mm(start_top_fnc), &self.font_bold);
		layer.use_text(netbios_name, self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);

		start_top_fnc -= self.line_height;
		layer.use_text("IP: ".to_string(), self.font_size, Mm(pos_key), Mm(start_top_fnc), &self.font_bold);
		layer.use_text(&host.ip, self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);

		start_top_fnc -= self.line_height;
		layer.use_text("Operating System: ".to_string(), self.font_size, Mm(pos_key), Mm(start_top_fnc), &self.font_bold);
		layer.use_text(&host.os, self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);

		start_top_fnc -= self.line_height;
		layer.use_text("Found via: ".to_string(), self.font_size, Mm(pos_key), Mm(start_top_fnc), &self.font_bold);
		layer.use_text(&gw, self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);

		start_top_fnc -= self.line_height;
		layer.use_text("Network: ".to_string(), self.font_size, Mm(pos_key), Mm(start_top_fnc), &self.font_bold);
		layer.use_text(&host.network, self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);

		if first_emerge {
			start_top_fnc -= self.line_height;
			layer.use_text("First seen in this scan".to_string(), self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);
		}
		if last_emerge {
			start_top_fnc -= self.line_height;
			layer.use_text("Last seen in this scan".to_string(), self.font_size, Mm(pos_val), Mm(start_top_fnc), &self.font_regular);
		}

		self.add_host_icon(layer, &host.os, &18.0, &242.0, &15.0, &15.0);

		start_top_fnc
	}

	/// Add a host icon to the layer on the given position in the given scale
	///
	/// # Arguments
	///
	/// * `layer` - Layer to add the icon onto
	/// * `host` - Operation System of the host
	/// * `from_left` - position from left
	/// * `from_bottom` - position from bottom
	/// * `scale_x` - scale the icon in X
	/// * `scale_y` - scale the icon in Y
	fn add_host_icon(&self, layer: &PdfLayerReference, host: &str, from_left: &f64, from_bottom: &f64, scale_x: &f64, scale_y: &f64) {
		let mut check_os = String::from(host);
		check_os.make_ascii_lowercase();
		let os_icon = match 1 {
			_ if { check_os.contains("android") || check_os.contains("ios") } => "static/assets/device-mobile.svg",
			_ if { check_os.contains("linux") } => "static/assets/device-linux.svg",
			_ if { check_os.contains("macos") } => "static/assets/device-apple.svg",
			_ if { check_os.contains("bsd") } => "static/assets/device-bsd.svg",
			_ if { check_os.contains("microsoft") } => "static/assets/device-windows.svg",
			_ if { check_os.contains("juniper") } => "static/assets/device-firewall.svg",
			_ => "static/assets/device-network.svg"
		};

		match Self::get_svg(os_icon) {
			None => {}
			Some(svg) => {
				svg.add_to_layer(&layer, SvgTransform {
					translate_x: Some(Mm(*from_left).into()),
					translate_y: Some(Mm(*from_bottom).into()),
					scale_x: Some(*scale_x),
					scale_y: Some(*scale_y),
					.. Default::default()
				});
			},
		}
	}

	/// Adds a filled square as a higlight background
	/// Is used to simulate a simple table with an even-odd color mechanism
	///
	/// # Arguments
	///
	/// * `even_line` - A boolean indicates if the current line is even or odd numbered.
	/// * `start_top` - Starting point of where the text is placed from bottom
	/// * `height` - height of the highlight rectangle
	/// * `left` - Position where the line starts on the left side
	/// * `right` - Position where the line ends on the right side
	/// * `layer` - PDF-Layer to draw the rectangle on
	///
	/// # Returns
	///
	/// A Boolean indicates if the next line is even or odd
	fn draw_highlight_line(&self, even_line: bool, start_top: &f64, height: &f64, left: &f64, right: &f64, layer: &PdfLayerReference) -> bool {
		let is_even_line = !even_line;
		let spacing_top = 1.8;
		let spacing_bottom = 1.2;
		if is_even_line {
			let bg_line = Line {
				points: vec![
					(Point::new(Mm(*left), Mm(start_top - spacing_bottom)), false),
					(Point::new(Mm(*left), Mm(start_top + height - spacing_top)), false),
					(Point::new(Mm(*right), Mm(start_top + height - spacing_top)), false),
					(Point::new(Mm(*right), Mm(start_top - spacing_bottom)), false),
				],
				is_closed: true,
				has_fill: true,
				has_stroke: true,
				is_clipping_path: false,
			};
			layer.set_fill_color( Color::Rgb(Rgb::new(0.99, 0.99, 0.99, None)) );
			layer.add_shape(bg_line);
		}
		layer.set_fill_color( Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)) );

		is_even_line
	}

	/// Draws a line
	///
	/// # Arguments
	///
	/// * `from_x` - Starting point from left
	/// * `from_y` - Starting point from bottom
	/// * `end_x` - End position from left
	/// * `end_y` - End position from bottom
	/// * `layer` - PDF-Layer to draw the line onto
	fn draw_line(&self, from_x: &f64, from_y: &f64, end_x: &f64, end_y: &f64, layer: &PdfLayerReference) {
		let line = Line {
			points: vec![ (Point::new(Mm(*from_x), Mm(*from_y)), false), (Point::new(Mm(*end_x), Mm(*end_y)), false) ],
			is_closed: false,
			has_fill: false,
			has_stroke: true,
			is_clipping_path: false,
		};
		layer.add_shape(line);
	}
}
