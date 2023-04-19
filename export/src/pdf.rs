use chrono::prelude::Local;
use String;
use std::collections::HashMap;
use printpdf::{
	pdf_document::PdfDocumentReference, Mm,
	PdfDocument, IndirectFontRef, PdfPageIndex, PdfLayerIndex, PdfLayerReference,
	svg::Svg, svg::SvgTransform,
	Rgb, Color, line::Line, point::Point,
};

pub struct Pdf<'a> {
	db: &'a mut sqlite::Database,
	network: &'a str,
	scan: &'a i64,
	font_regular: IndirectFontRef,
	font_bold: IndirectFontRef,
	max_bottom: f64,
	min_bottom: f64,
	_max_left: f64,
	min_left: f64,
}

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
		let (doc, page, layer) = PdfDocument::new("Network-Scan ".to_string() + &scan.to_string(), Mm(210.0), Mm(297.0), "Page 1");
		//let mut font_regular_reader = std::io::Cursor::new(include_bytes!("../assets/Roboto-Light.ttf").as_ref());
		//let mut font_bold_reader = std::io::Cursor::new(include_bytes!("../assets/Roboto-Black.ttf").as_ref());

		let mut pdf = Pdf {
			db,
			network: &network,
			scan: &scan,
			font_regular: doc.add_builtin_font(printpdf::BuiltinFont::Helvetica).unwrap(), // doc.add_external_font(&mut font_regular_reader).unwrap(),
			font_bold: doc.add_builtin_font(printpdf::BuiltinFont::HelveticaBold).unwrap(), // doc.add_external_font(&mut font_bold_reader).unwrap(),
			max_bottom:  260.0,
			min_bottom: 20.0,
			_max_left: 190.0,
			min_left: 20.0,
		};

		pdf.create_title_page(&doc, &page, &layer);
		pdf.add_network(&doc);
		pdf.add_hosts(&doc);

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

		let svg_logo = Svg::parse(include_str!("../assets/logo.svg").as_ref()).unwrap();
		svg_logo.add_to_layer(&layer, SvgTransform {
			translate_x: Some(Mm(70.0).into()),
			translate_y: Some(Mm(230.0).into()),
			scale_x: Some(3.0),
			scale_y: Some(3.0),
			.. Default::default()
		});

		layer.use_text("NetworkDiscover".to_string(), 48.0, Mm(40.0), Mm(180.0), &self.font_bold);
		layer.use_text("Scan: ".to_string() + &self.scan.to_string(), 24.0, Mm(30.0), Mm(110.0), &self.font_bold);

		let scan_date = match db::Scan::load(self.db, self.scan) {
			Some(scan) => scan.start_time.and_local_timezone(Local::now().timezone()).unwrap().format("%Y-%m-%d %H:%M:%S %:z").to_string(),
			None => "Unknown".to_string()
		};
		layer.use_text("Date: ".to_string() + &scan_date, 24.0, Mm(30.0), Mm(95.0), &self.font_regular);
	}

	/// Create a page with the whole network visualized
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document to add all hosts
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
		let center_h = self.min_bottom + (self.max_bottom - self.min_bottom) / 2.0;
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
	fn init_start_pos_per_level(nodes: &HashMap<i64, Node>, distance: f64, center: f64) -> HashMap<i64, f64> {
		let mut start_pos: HashMap<i64, f64> = HashMap::new();
		let nodes_per_level = Self::get_nodes_per_level(&nodes);
		for (k, v) in nodes_per_level {
			let pos = center - ((v as f64) * distance / 2.0);
			start_pos.insert(k, pos);
		}
		start_pos
	}

	/// Returns the number of nodes per level.
	///
	/// # Arguments
	///
	/// * `nodes` - Reference to the Nodes HashMap which has already calculated levels
	///
	/// # Result
	///
	/// A HashMap where the key is the level and the value is the number of nodes on that level
	fn get_nodes_per_level(nodes: &HashMap<i64, Node>) -> HashMap<i64, i64> {
		let mut nums: HashMap<i64, i64> = HashMap::new();
		for (_, node) in nodes {
			let mut num = *nums.get(&node.level).unwrap_or(&0);
			num = num + (1 as i64);
			nums.insert(node.level, i64::from(num));
		}
		nums
	}

	/// Calculates the distances for each node compared to the first node.
	/// The distance is changed on the node referece.
	///
	/// # Arguments
	///
	/// * `current` - The node key to process the edges
	/// * `distance` - Distance for the given node
	/// * `nodes` - HashMap of all nodes
	fn build_node_distances(current: i64, distance: i64, nodes: &mut HashMap<i64, Node>) {
		let mut edges: Vec<i64> = vec![];
		match nodes.get_mut(&current) {
			Some(n) => {
				n.level = i64::from(distance);
				edges.append(&mut n.edges);
			}
			_ => {}
		}
		for next in edges {
			Self::build_node_distances(next, distance + 1, nodes);
		}
	}

	/// Add a host icon with a label below it
	///
	/// # Arguments
	///
	/// * `layer` - Layer to add the icon to
	/// * `left` - Position from the left
	/// * `bottom` - Position from the bottom
	/// * `label` - Label to show below
	/// * `os` - Operating System to find the correct icon
	fn add_host_with_label(&self, layer: &PdfLayerReference, left: &f64, bottom: &f64, label: &str, os: &str) {
		self.add_host_icon(&layer, os, left, bottom, &3.0, &3.0);
		layer.use_text(label, 7.0, Mm(left - 8.0), Mm(bottom - 2.6), &self.font_regular);
	}

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
	fn add_page(&self, doc: &PdfDocumentReference, title: &str) -> PdfLayerReference {
		let (page_index, layer_index) = doc.add_page(Mm(210.0), Mm(297.0), String::from(title));
		self.add_header_and_footer(doc, &page_index, &layer_index);

		let layer = doc.get_page(page_index).get_layer(layer_index);
		layer.set_outline_color( Color::Rgb(Rgb::new(0.8, 0.8, 0.8, None)) );
		layer.set_fill_color( Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)) );
		layer.set_outline_thickness(0.2);

		layer
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

		let font_size = 11.0;
		let line_height = 6.0;
		let mut start_top = 266.0;

		start_top = self.add_hosts_header(&layer, host, &start_top, &line_height, &font_size);

		start_top -= 20.0;
		layer.use_text("Found Services:".to_string(), font_size + 4.0, Mm(20.0), Mm(start_top), &self.font_bold);
		self.draw_line(&15.0, &(start_top - 2.0), &200.0, &(start_top - 2.0), &layer);

		let mut even_line = true;
		start_top -= line_height / 2.0;
		db::Port::load(self.db, &host.hist_id).iter()
			.for_each(|port| {
				start_top -= line_height;
				if start_top < 20.0 {
					layer = self.add_page(doc, &title);
					start_top = 266.0;
				}
				even_line = self.draw_highlight_line(even_line, &start_top, &line_height, &20.0, &200.0, &layer);

				layer.use_text(port.port.to_string() + "/" + &port.protocol, font_size, Mm(25.0), Mm(start_top), &self.font_regular);
				layer.use_text(String::from(&port.service), font_size, Mm(50.0), Mm(start_top), &self.font_regular);
				layer.use_text(String::from(&port.product), font_size, Mm(85.0), Mm(start_top), &self.font_regular);
			});

		start_top -= 16.0;
		layer.use_text("Found Vulnerabilities:".to_string(), font_size + 4.0, Mm(20.0), Mm(start_top), &self.font_bold);
		self.draw_line(&15.0, &(start_top - 2.0), &200.0, &(start_top - 2.0), &layer);

		even_line = true;
		start_top -= line_height * 1.8;
		let mut grouped: HashMap<String, Vec<&db::Cve>> = HashMap::new();
		let binding = db::Cve::from_host_hist(self.db, &host.hist_id);
		binding.iter()
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
			layer.use_text(String::from(group).to_uppercase(), font_size, Mm(23.0), Mm(start_top), &self.font_bold);
			layer.use_text(String::from("CVSS"), font_size, Mm(178.0), Mm(start_top), &self.font_bold);
			self.draw_line(&20.0, &(start_top - 2.0), &200.0, &(start_top - 2.0), &layer);

			start_top -= 2.2;
			cves.iter().for_each(|cve| {
				start_top -= line_height;
				if start_top < 20.0 {
					layer = self.add_page(doc, &title);
					start_top = 266.0;
				}
				even_line = self.draw_highlight_line(even_line, &start_top, &line_height, &23.0, &200.0, &layer);

				layer.use_text(String::from(&cve.type_id), font_size, Mm(25.0), Mm(start_top), &self.font_regular);
				layer.use_text(cve.cvss.to_string(), font_size, Mm(180.0), Mm(start_top), &self.font_regular);
			})
		});
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
		let svg_logo = Svg::parse(include_str!("../assets/logo.svg").as_ref()).unwrap();
		svg_logo.add_to_layer(&layer, SvgTransform {
			translate_x: Some(Mm(10.0).into()),
			translate_y: Some(Mm(280.0).into()),
			scale_x: Some(1.0),
			scale_y: Some(1.0),
			.. Default::default()
		});
		layer.use_text("NetworkDiscover Scan: ".to_string() + &self.scan.to_string(), 16.0, Mm(35.0), Mm(281.5), &self.font_bold);
		layer.use_text(Local::now().format("%Y-%m-%d %H:%M:%S %:z").to_string(), 10.0, Mm(154.5), Mm(6.0), &self.font_regular);

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
	}

	/// Prints a simple header on the given PDF-Layer with all needed information from the given host.
	///
	/// # Arguments
	///
	/// * `layer` - The PDFLayer to print the header on
	/// * `host` - Host struct to get all information from
	/// * `start_top` - Position from bottom where to start with the header
	/// * `line_height` - Height of a text line
	/// * `font_size` - Font size to use
	///
	/// # Returns
	///
	/// The new position form bottom where the next text has to be oriented at
	fn add_hosts_header(&mut self, layer: &PdfLayerReference, host: &db::Host, start_top: &f64, line_height: &f64, font_size: &f64) -> f64 {
		let mut start_top_fnc = *start_top;

		let gw = db::Host::get_gateway(self.db, &host.hist_id, &self.scan).map_or_else(|| "0.0.0.0".to_string(), |host| host.ip);
		let first_emerge = db::Host::find_first_emerge(self.db, &host.ip).map_or(false, |h| h.id == host.hist_id);
		let last_emerge = db::Host::find_last_emerge(self.db, &host.ip).map_or(false, |h| h.id == host.hist_id);

		// Text
		layer.use_text("Host: ".to_string() + &host.ip, *font_size, Mm(50.0), Mm({ start_top_fnc -= line_height; start_top_fnc }), &self.font_regular);
		layer.use_text("Operating System: ".to_string() + &host.os, *font_size, Mm(50.0), Mm({ start_top_fnc -= line_height; start_top_fnc }), &self.font_regular);
		layer.use_text("Found via: ".to_string() + &gw, *font_size, Mm(50.0), Mm({ start_top_fnc -= line_height; start_top_fnc }), &self.font_regular);
		layer.use_text("Network: ".to_string() + &host.network, *font_size, Mm(50.0), Mm({ start_top_fnc -= line_height; start_top_fnc }), &self.font_regular);
		if first_emerge {
			layer.use_text("First seen in this scan".to_string(), *font_size, Mm(50.0), Mm({ start_top_fnc -= line_height; start_top_fnc }), &self.font_regular);
		}
		if last_emerge {
			layer.use_text("Last seen in this scan".to_string(), *font_size, Mm(50.0), Mm({ start_top_fnc -= line_height; start_top_fnc }), &self.font_regular);
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
			_ if { check_os.contains("linux") } => include_str!("../assets/device-linux.svg"),
			_ if { check_os.contains("microsoft") } => include_str!("../assets/device-windows.svg"),
			_ if { check_os.contains("macos") } => include_str!("../assets/device-apple.svg"),
			_ if { check_os.contains("juniper") } => include_str!("../assets/device-firewall.svg"),
			_ if { check_os.contains("android") || check_os.contains("ios") } => include_str!("../assets/device-mobile.svg"),
			_ => include_str!("../assets/device-network.svg")
		};
		let svg_logo = Svg::parse(os_icon.as_ref()).unwrap();
		svg_logo.add_to_layer(&layer, SvgTransform {
			translate_x: Some(Mm(*from_left).into()),
			translate_y: Some(Mm(*from_bottom).into()),
			scale_x: Some(*scale_x),
			scale_y: Some(*scale_y),
			.. Default::default()
		});
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
