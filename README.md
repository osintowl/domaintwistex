# DomainTwistex

DomainTwistex is an Elixir library that provides domain name permutation and typosquatting detection capabilities, powered by the Rust-based twistrs library.

## Features

- Generate domain permutations for typosquatting detection
- Support for various permutation types:
  - Character omission
  - Character replacement
  - Character insertion
  - Character swapping
  - Common typos
  - Homoglyphs
- MX record validation for generated domains
- Concurrent domain analysis

## Installation

Add `domaintwistex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:domaintwistex, "~> 0.1.0"}
  ]
end
```

### Prerequisites

- Elixir 1.18 or later
- Rust toolchain (for compiling the native extension)

## Usage

```elixir
# Generate domain permutations
domains = DomainTwistex.analyze_domain("example.com")

# Get domains with MX records
live_domains = DomainTwistex.get_live_mx_domains("example.com")

# Customize permutation options
domains = DomainTwistex.analyze_domain("example.com", 
  types: [:addition, :omission, :homoglyph])
```

## Configuration

By default, all permutation types are enabled. You can specify which types to use:

- `:addition` - Character addition
- `:omission` - Character omission
- `:homoglyph` - Homoglyph substitution
- `:repetition` - Character repetition
- `:replacement` - Character replacement
- `:subdomain` - Subdomain insertion
- `:transposition` - Character transposition
- `:vowel_swap` - Vowel swapping
- `:various` - Various common typos

## Performance

The library uses Rust NIFs for domain permutation generation, providing excellent performance while maintaining safety through the Rustler framework.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the BSD-3-Clause License.

### Acknowledgments

This project includes code from [twistrs](https://github.com/haveibeensquatted/twistrs), which is licensed under the MIT License.
Copyright (c) 2023 JuxhinDB

## Author

nix2intel (@nix2intel)
