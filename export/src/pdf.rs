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
		let (doc, page1, layer1) = PdfDocument::new("Network-Scan ".to_string() + &scan.to_string(), Mm(210.0), Mm(297.0), "Page 1");
		//let mut font_regular_reader = std::io::Cursor::new(include_bytes!("../assets/Roboto-Light.ttf").as_ref());
		//let mut font_bold_reader = std::io::Cursor::new(include_bytes!("../assets/Roboto-Black.ttf").as_ref());

		let mut pdf = Pdf {
			db,
			network: &network,
			scan: &scan,
			font_regular: doc.add_builtin_font(printpdf::BuiltinFont::Helvetica).unwrap(), // doc.add_external_font(&mut font_regular_reader).unwrap(),
			font_bold: doc.add_builtin_font(printpdf::BuiltinFont::HelveticaBold).unwrap(), // doc.add_external_font(&mut font_bold_reader).unwrap(),
		};

		pdf.create_title_page(&doc, &page1, &layer1);
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

	/// Adds one or more pages for a Host to the PDF
	///
	/// # Arguments
	///
	/// * `doc` - Reference to the PDF Document
	/// * `host` - Reference to the Host
	fn add_host_page(&mut self, doc: &PdfDocumentReference, host: &db::Host) {
		let (page_index, layer_index) = doc.add_page(Mm(210.0), Mm(297.0), "Host ".to_string() + &host.ip);
		self.add_header_and_footer(doc, &page_index, &layer_index);
		let layer = doc.get_page(page_index).get_layer(layer_index);

		layer.set_outline_color( Color::Rgb(Rgb::new(0.8, 0.8, 0.8, None)) );
		layer.set_fill_color( Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)) );
		layer.set_outline_thickness(0.2);

		let font_size = 11.0;
		let line_height = 6.0;
		let mut start_top = 266.0;

		start_top = self.add_hosts_header(&layer, host, &start_top, &line_height, &font_size);

		start_top -= 20.0;
		layer.use_text("Found Services:".to_string(), font_size + 4.0, Mm(20.0), Mm(start_top), &self.font_bold);
		self.draw_line(&(start_top - 2.0), &15.0, &200.0, &layer);

		let mut even_line = true;
		start_top -= line_height / 2.0;
		db::Port::load(self.db, &host.hist_id).iter()
			.for_each(|port| {
				start_top -= line_height;
				even_line = self.draw_highlight_line(even_line, &start_top, &line_height, &20.0, &200.0, &layer);

				layer.use_text(port.port.to_string() + "/" + &port.protocol, font_size, Mm(25.0), Mm(start_top), &self.font_regular);
				layer.use_text(String::from(&port.service), font_size, Mm(50.0), Mm(start_top), &self.font_regular);
				layer.use_text(String::from(&port.product), font_size, Mm(85.0), Mm(start_top), &self.font_regular);
			});

		start_top -= 16.0;
		layer.use_text("Found Vulnerabilities:".to_string(), font_size + 4.0, Mm(20.0), Mm(start_top), &self.font_bold);
		self.draw_line(&(start_top - 2.0), &15.0, &200.0, &layer);

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
			layer.use_text(String::from(group), font_size + 2.0, Mm(25.0), Mm(start_top), &self.font_bold);
			self.draw_line(&(start_top - 2.0), &23.0, &200.0, &layer);
			start_top -= 2.2;

			cves.iter().for_each(|cve| {
				start_top -= line_height;
				even_line = self.draw_highlight_line(even_line, &start_top, &line_height, &30.0, &200.0, &layer);

				layer.use_text(String::from(&cve.type_id), font_size, Mm(35.0), Mm(start_top), &self.font_regular);
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

		// The Icon
		let mut check_os = String::from(&host.os);
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
			translate_x: Some(Mm(18.0).into()),
			translate_y: Some(Mm(242.0).into()),
			scale_x: Some(15.0),
			scale_y: Some(15.0),
			.. Default::default()
		});

		start_top_fnc
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
	/// * `start_top` - Starting point from bottom where the line should be shown
	/// * `left` - Position where the line starts on the left side
	/// * `right` - Position where the line ends on the right side
	/// * `layer` - PDF-Layer to draw the line onto
	fn draw_line(&self, start_top: &f64, left: &f64, right: &f64, layer: &PdfLayerReference) {
		let line = Line {
			points: vec![ (Point::new(Mm(*left), Mm(*start_top)), false), (Point::new(Mm(*right), Mm(*start_top)), false) ],
			is_closed: false,
			has_fill: false,
			has_stroke: true,
			is_clipping_path: false,
		};
		layer.add_shape(line);
	}
}
