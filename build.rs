use std::env;
use std::fs;
use std::path::Path;

// generate functions to serve embedded ui from "ui" directory.
// this is aimed to have an UI with a single binary distribution.
fn main() {
    let ui_dir = "ui";
    println!("cargo:rerun-if-changed={}", ui_dir);
    println!("cargo:rerun-if-changed=build.rs");
    gen_embedded_ui(ui_dir);
}

fn gen_embedded_ui(base: &str) {
    let mut ui_resource = vec![];
    list_files(Path::new(base), Path::new(base), &mut ui_resource);
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("embedded-ui.rs");

    let gen_service_fn = |name| {
        format!(
            r#"
#[allow(dead_code)]
async fn get_{id}() -> impl IntoResponse {{ 
    const BYTES: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/{base}/{name}"));
    let header = Headers(vec![("content-type", mime_guess::from_path("{name}").first_or_text_plain().to_string())]);
    (header,BYTES) 
}}"#,
            id = escape_name(name),
            base = base,
            name = name,
        )
    };

    let routes = ui_resource
        .iter()
        .map(|f| {
            format!(
                r#".route("/{}", get(get_{})).boxed()"#,
                escape_path(f),
                escape_name(f)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let resources = ui_resource
        .iter()
        .map(String::as_str)
        .map(gen_service_fn)
        .collect::<Vec<_>>()
        .join("\n");

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
    {routes}
    // .boxed()
}}
{resources}
"#,
            routes = routes,
            resources = resources
        ),
    )
    .unwrap();
}

fn escape_path(s: &str) -> &str {
    s.strip_suffix("index.html").unwrap_or(s)
}

fn escape_name(s: &str) -> String {
    s.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
}

fn list_files(base: &Path, dir: &Path, list: &mut Vec<String>) {
    for entry in dir.read_dir().expect("read_dir") {
        let entry = entry.expect("read_dir_entry");
        let p = entry.path();
        if p.file_name().unwrap().to_str().unwrap().starts_with('.') {
            continue;
        }
        if p.is_file() {
            list.push(p.strip_prefix(base).unwrap().to_str().unwrap().to_owned());
        } else if p.is_dir() {
            list_files(base, &p, list)
        }
    }
}
