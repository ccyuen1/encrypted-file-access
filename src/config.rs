use argon2::{Algorithm, Argon2, Params, Version};

/// Create a default Argon2 instance for our use.
pub fn argon2_config() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19_456u32, 2u32, 1u32, Some(32usize))
            .expect("Failed to create Argon2 params"),
    )
}

/// Create a default CSV [`WriterBuilder`] for our use.
pub fn csv_writer_builder() -> csv::WriterBuilder {
    let mut builder = csv::WriterBuilder::new();
    builder
        .has_headers(false)
        .delimiter(b',')
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary);
    builder
}
