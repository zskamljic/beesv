use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

pub fn generate_seed(mnemonic: &str, password: &str) -> [u8; 64] {
    let salt = format!("mnemonic{password}");

    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

    return seed;
}

#[cfg(test)]
mod tests {
    use crate::bip39::generate_seed;

    #[test]
    fn generate_seed_generates_correct() {
        let mnemonic = "initial devote cake drill toy hidden foam gasp film palace flip clump";
        let seed = generate_seed(mnemonic, "");

        assert_eq!(
            "88a6b54bf042d0ba673e497dd283feeca6a1d0fd31cf26d8b7e115f2b3cc92294541855a9c0e74a3c3b87a5aee5adc89faf0702721b6b8af31c0d2b403aba531",
            seed.iter().map(|b|format!("{b:02x}")).collect::<String>()
        );
    }
}
