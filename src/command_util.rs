use std::process::Output;

pub trait CombinedString {
    fn combined_string(&self) -> String;
}

impl CombinedString for Output {
    fn combined_string(&self) -> String {
        let mut outs = Vec::new();
        let mut add = |vec: &Vec<u8>| {
            if !vec.is_empty() {
                outs.push(String::from_utf8_lossy(vec).to_string());
            }
        };
        add(&self.stdout);
        add(&self.stderr);
        outs.join(" / ")
    }
}
