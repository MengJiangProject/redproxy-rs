mod filter;
mod parser;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    target: String,
    filter: Option<String>,
}

impl Rule {}
