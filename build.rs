use std::env;
use std::fs;
use std::path::Path;
fn main() {
    let ui_dir = "ui";
    println!("cargo:rerun-if-changed={}", ui_dir);
    let ui_resource = list_files(Path::new(ui_dir));
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("embedded-ui.rs");

    let gen_service_fn = |name| {
        format!(
            r#"
#[allow(dead_code)]
async fn get_{id}() -> impl IntoResponse {{ 
    let bytes: &'static [u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/{base}/{name}"));
    let header = Headers(vec![("content-type", mime_guess::from_path("{name}").first_or_text_plain().to_string())]);
    (header,bytes) 
}}"#,
            id = escape_name(name),
            base = ui_dir,
            name = name,
        )
    };

    fs::write(
        &dest_path,
        format!(
            r#"
use axum::{{
    handler::get,
    Router,
    routing::BoxRoute,
    response::{{IntoResponse, Headers}},
}};
#[allow(dead_code)]
pub fn app() -> Router<BoxRoute> {{
    Router::new()
    {}
    .boxed()
}}
{}
"#,
            ui_resource
                .iter()
                .map(|f| format!(
                    r#".route("/{}", get(get_{}))"#,
                    escape_path(f),
                    escape_name(f)
                ))
                .collect::<Vec<_>>()
                .join("\n"),
            ui_resource
                .iter()
                .map(String::as_str)
                .map(gen_service_fn)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}

fn escape_path(s: &str) -> &str {
    s.strip_suffix("index.html").unwrap_or(s)
}

fn escape_name(s: &str) -> String {
    s.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
}

fn list_files(dir: &Path) -> Vec<String> {
    let mut ret = vec![];
    let this = dir.read_dir().expect("read_dir");
    for entry in this {
        let entry = entry.expect("read_dir_entry");
        ret.push(
            entry
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
        );
    }
    ret
}
