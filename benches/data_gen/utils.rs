use rand::Rng;

/// Alphabet as an &str
pub const ALPHA: &str = "abcdefghijklmnopqrstuvwxyz";
pub fn random_string(n: u32, charset: &str) -> String {
    let mut rng = rand::thread_rng();

    let mut res = "".to_string();
    for _i in 0..n as usize {
        let random_index: usize = rng.gen_range(0..charset.len());
        res.push_str(&charset.chars().nth(random_index).unwrap().to_string());
    }
    res
}
