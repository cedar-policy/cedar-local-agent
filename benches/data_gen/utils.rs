use rand::Rng;

/// Alphabet as an &str
pub const ALPHA: &str = "abcdefghijklmnopqrstuvwxyz";
#[allow(clippy::single_char_add_str)]
pub fn random_string(n: u32, charset: &str) -> String {
    let mut rng = rand::rng();

    let mut res = "".to_string();
    for _i in 0..n as usize {
        let random_index: usize = rng.random_range(0..charset.len());
        res.push(charset.chars().nth(random_index).unwrap());
    }
    res
}
