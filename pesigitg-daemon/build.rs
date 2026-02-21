macro_rules! rustc_env {
    ($key:expr, $value:expr) => {
        println!("cargo:rustc-env={}={}", $key, $value)
    };
}

fn main() {
    rustc_env!("TARGET", std::env::var("TARGET").unwrap());

    let rustc = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .expect("failed to run rustc");
    let rustc_version = String::from_utf8(rustc.stdout).unwrap();
    rustc_env!("RUSTC_VERSION", rustc_version.trim());

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    rustc_env!("BUILD_DATE", date);
}
