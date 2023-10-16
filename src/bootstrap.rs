use serde::Deserialize;
use std::path::Path;
use std::{fs::File, net::SocketAddr};

const BOOTSTRAPPERS_FILE_PATH: &str = "./genesis/bootstrappers.json";

#[derive(Debug, Deserialize)]
pub struct Bootstrapper {
    pub id: String,
    pub ip: SocketAddr,
}

#[derive(Debug, Deserialize)]
pub struct Bootstrappers {
    pub mainnet: Vec<Bootstrapper>,
    pub fuji: Vec<Bootstrapper>,
}

impl Bootstrappers {
    pub fn read_boostrap_json() -> Bootstrappers {
        let json_file_path = Path::new(BOOTSTRAPPERS_FILE_PATH);

        let file = File::open(json_file_path).expect("Bootstrapper file not found");

        let parsed: Bootstrappers =
            serde_json::from_reader(file).expect("Error while parsing Bootstrapper file");

        parsed
    }
}
