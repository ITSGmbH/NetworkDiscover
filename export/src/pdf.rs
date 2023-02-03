use chrono::prelude::Local;
use String;
use printpdf::{
	pdf_document::PdfDocumentReference, Mm,
	PdfDocument, PdfPageIndex, PdfLayerIndex, IndirectFontRef,
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
	pub fn export(db: &mut sqlite::Database, network: String, scan: i64) -> String {
		let (doc, page1, layer1) = PdfDocument::new("Network-Scan ".to_string() + &scan.to_string(), Mm(210.0), Mm(297.0), "Page 1");
		let mut font_regular_reader = std::io::Cursor::new(include_bytes!("../assets/Roboto-Regular.ttf").as_ref());
		let mut font_bold_reader = std::io::Cursor::new(include_bytes!("../assets/Roboto-Black.ttf").as_ref());

		let mut pdf = Pdf {
			db,
			network: &network,
			scan: &scan,
			font_regular: doc.add_external_font(&mut font_regular_reader).unwrap(),
			font_bold: doc.add_external_font(&mut font_bold_reader).unwrap(),
		};

		pdf.create_title_page(&doc, &page1, &layer1);
		pdf.add_hosts(&doc);

		let bin_pdf = doc.save_to_bytes().unwrap();
		String::from_utf8_lossy(&bin_pdf).to_string()
	}

	fn create_title_page(&mut self, doc: &PdfDocumentReference, page: &PdfPageIndex, layer: &PdfLayerIndex) {
		let title_layer = doc.get_page(*page).get_layer(*layer);

		let svg_logo = Svg::parse(include_str!("../assets/logo.svg").as_ref()).unwrap();
		svg_logo.add_to_layer(&title_layer, SvgTransform {
			translate_x: Some(Mm(70.0).into()),
			translate_y: Some(Mm(230.0).into()),
			scale_x: Some(3.0),
			scale_y: Some(3.0),
			.. Default::default()
		});

		title_layer.use_text("NetworkDiscover".to_string(), 48.0, Mm(40.0), Mm(180.0), &self.font_bold);
		title_layer.use_text("Scan: ".to_string() + &self.scan.to_string(), 24.0, Mm(30.0), Mm(110.0), &self.font_bold);

		let scan_date = match db::Scan::load(self.db, self.scan) {
			Some(scan) => scan.start_time.and_local_timezone(Local::now().timezone()).unwrap().format("%Y-%m-%d %H:%M:%S %:z").to_string(),
			None => "Unknown".to_string()
		};
		title_layer.use_text("Date: ".to_string() + &scan_date, 24.0, Mm(30.0), Mm(95.0), &self.font_regular);
	}

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

	fn add_hosts(&mut self, doc: &PdfDocumentReference) {
		db::Host::list_from_network(self.db, self.network, self.scan)
			.iter()
			.for_each(|host| self.add_host_page(&doc, &host));
	}

	fn add_host_page(&mut self, doc: &PdfDocumentReference, host: &db::Host) {
		let (page_index, layer_index) = doc.add_page(Mm(210.0), Mm(297.0), "Host ".to_string() + &host.ip);
		self.add_header_and_footer(doc, &page_index, &layer_index);
		let layer = doc.get_page(page_index).get_layer(layer_index);

		layer.set_outline_color( Color::Rgb(Rgb::new(0.8, 0.8, 0.8, None)) );
		layer.set_fill_color( Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)) );
		layer.set_outline_thickness(0.2);

		let gw = db::Host::get_gateway(self.db, &host.hist_id, &self.scan).map_or_else(|| "0.0.0.0".to_string(), |host| host.ip);
		let font_size = 11.0;
		let line_height = 6.0;
		let mut start_top = 266.0;

		self.add_hosts_icon(doc, &page_index, &layer_index, &host.os);
		layer.use_text("Operating System: ".to_string() + &host.os, font_size, Mm(50.0), Mm({ start_top -= line_height; start_top }), &self.font_regular);
		layer.use_text("Host: ".to_string() + &host.ip, font_size, Mm(50.0), Mm({ start_top -= line_height; start_top }), &self.font_regular);
		layer.use_text("Network: ".to_string() + &host.network, font_size, Mm(50.0), Mm({ start_top -= line_height; start_top }), &self.font_regular);
		layer.use_text("Found via: ".to_string() + &gw, font_size, Mm(50.0), Mm({ start_top -= line_height; start_top }), &self.font_regular);

		start_top = 220.0;
		layer.use_text("Found Services:".to_string(), font_size + 4.0, Mm(20.0), Mm(start_top), &self.font_bold);
		let under_line = Line {
			points: vec![ (Point::new(Mm(15.0), Mm(start_top - 2.2)), false), (Point::new(Mm(200.0), Mm(start_top - 2.2)), false) ],
			is_closed: false,
			has_fill: false,
			has_stroke: true,
			is_clipping_path: false,
		};
		layer.add_shape(under_line);

		let mut even_line = true;
		let spacing_top = 1.8;
		let spacing_bottom = 1.2;
		start_top = 217.0;
		db::Port::load(self.db, &host.hist_id).iter()
			.for_each(|port| {
				start_top -= line_height;
				if { even_line = !even_line; even_line } {
					let bg_line = Line {
						points: vec![
							(Point::new(Mm(20.0), Mm(start_top - spacing_bottom)), false),
							(Point::new(Mm(20.0), Mm(start_top + line_height - spacing_top)), false),
							(Point::new(Mm(200.0), Mm(start_top + line_height - spacing_top)), false),
							(Point::new(Mm(200.0), Mm(start_top - spacing_bottom)), false),
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
				layer.use_text(port.port.to_string() + "/" + &port.protocol, font_size, Mm(25.0), Mm(start_top), &self.font_regular);
				layer.use_text(String::from(&port.service), font_size, Mm(50.0), Mm(start_top), &self.font_regular);
				layer.use_text(String::from(&port.product), font_size, Mm(85.0), Mm(start_top), &self.font_regular);
			});
	}

	fn add_hosts_icon(&self, doc: &PdfDocumentReference, page_index: &PdfPageIndex, layer_index: &PdfLayerIndex, os: &str) {
		let layer = doc.get_page(*page_index).get_layer(*layer_index);

		let mut check_os = String::from(os);
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
	}
}
