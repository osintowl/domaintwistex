# DomainTwistex

DomainTwistex is an Elixir library that provides domain name permutation and typosquatting detection capabilities, powered by the Rust-based twistrs library. Version 0.4.0 introduces enhanced concurrency features and improved domain validation.

## Features

- Generate domain permutations for typosquatting detection
- Comprehensive domain validation including:
  - IP resolution
  - MX record validation
  - TXT record checking
  - Nameserver verification
  - Server response analysis
- High-performance concurrent domain analysis
- Rust-powered permutation generation

## Installation

Add `domaintwistex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:domaintwistex, "~> 0.4.0"}
  ]
end
```

### Prerequisites

- Elixir 1.18 or later
- Rust toolchain (for compiling the native extension)

## Usage

```elixir
# Basic domain analysis
domains = DomainTwistex.analyze_domain("example.com")

# Get domains with MX records
live_domains = DomainTwistex.get_live_mx_domains("example.com")

# Advanced usage with custom options
domains = DomainTwistex.analyze_domain("example.com",
  max_concurrency: 50,
  timeout: 5000,
  ordered: false
)
```

## Configuration

### Performance Options

New in 0.4.0:
- `max_concurrency`: Maximum number of concurrent tasks (default: System.schedulers_online() * 2)
- `timeout`: Timeout for each task in milliseconds (default: 5000)
- `ordered`: Maintain result order (default: false)

## Performance

The library uses:
- Rust NIFs for domain permutation generation
- Concurrent task processing for domain validation
- Default system DNS resolution

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
```
