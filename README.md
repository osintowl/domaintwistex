# DomainTwistex

DomainTwistex is a pure Elixir library for domain name permutation generation and typosquatting detection. It generates domain permutations, resolves them concurrently, and enriches results with DNS, WHOIS, and content similarity data.

## Features

- **18 permutation algorithms** — Addition, Bitsquatting, Hyphenation, Insertion, Omission, Repetition, Replacement, Subdomain, Transposition, VowelSwap, VowelShuffle, DoubleVowelInsertion, Keyword, TLD, FauxTLD, Mapped, and Homoglyph
- **Concurrent DNS validation** — parallel A/CNAME/MX/TXT/DMARC/NS/wildcard lookups
- **WHOIS/RDAP enrichment** — optional registrar and date lookups via RDAP-first, WHOIS-fallback
- **Content similarity** — shingle-based Jaccard similarity for phishing page detection
- **Fuzzy matching scores** — Jaro-Winkler, Levenshtein, character diff, keyboard proximity
- **SPF record parsing** — with provider categorization (transactional email, marketing, etc.)
- **Distributed scanning** — split work across Erlang nodes
- **CLI task** — `mix twist` for command-line scanning

## Installation

Add `domaintwistex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:domaintwistex, "~> 0.8.0"}
  ]
end
```

### Prerequisites

- Elixir 1.17 or later
- OTP 27+ (for `String.jaro_distance/2`)

No Rust toolchain required — permutation generation is pure Elixir.

## Usage

### Domain Analysis

```elixir
# Full analysis — resolves original + all permutations concurrently
result = DomainTwistex.Twist.analyze_domain("example.com")

# Returns:
%{
  domain: "example.com",
  original: %{
    fqdn: "example.com",
    tld: "com",
    resolvable: true,
    ip_addresses: ["93.184.216.34"],
    public_ips: ["93.184.216.34"],
    mx_records: [...],
    nameservers: [...],
    wildcard: false,
    ...
  },
  permutations: [
    %{kind: "Tld", fqdn: "example.co.uk", ip_addresses: [...], ...},
    %{kind: "Homoglyph", fqdn: "examp1e.com", ip_addresses: [...], ...},
    ...
  ],
  stats: %{permutation_count: 523}
}

# With options
result = DomainTwistex.Twist.analyze_domain("example.com",
  max_concurrency: 50,
  timeout: 10_000,
  whois: true,
  content_hash: true
)
```

### MX-Only Filter

```elixir
# Returns only permutations with MX records (potential phishing targets)
result = DomainTwistex.Twist.get_live_mx_domains("example.com")
# => %{domain: "example.com", original: %{...}, permutations: [...], stats: %{mx_count: 12, permutation_count: 523}}
```

### Permutation Generation (No Resolution)

```elixir
# Just generate permutations without DNS checks
permutations = DomainTwistex.Twist.get_permutations("example.com")
# => [%{fqdn: "examplea.com", tld: "com", kind: "Addition"}, ...]

# With options
permutations = DomainTwistex.Twist.get_permutations("example.com", faux_tld: true)
```

### Distributed Scanning

```elixir
# Split work across connected nodes
Node.connect(:"node2@host")
results = DomainTwistex.Twist.analyze_distributed("example.com")
```

### CLI

```bash
mix twist example.com
mix twist -c 100 -w example.com
mix twist --format json -o results.json example.com
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_concurrency` | `System.schedulers_online() * 2` | Max concurrent DNS check tasks |
| `timeout` | `15000` | Timeout per domain check (ms) |
| `ordered` | `false` | Maintain permutation order in results |
| `whois` | `true` | Enable WHOIS/RDAP lookups (slower) |
| `content_hash` | `false` | Enable content similarity checking (slower) |

### Permutation Options (for `generate_permutations/2`)

| Option | Default | Description |
|--------|---------|-------------|
| `faux_tld` | `false` | Include FauxTld permutations (adds ~14K entries) |
| `double_vowel` | `true` | Include DoubleVowelInsertion |
| `vowel_shuffle` | `true` | Include VowelShuffle |

## Inspection Results

Each permutation result includes:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Permutation type (e.g., "Homoglyph", "Tld") |
| `fqdn` | string | Fully qualified domain name |
| `tld` | string | Top-level domain |
| `resolvable` | boolean | Whether the domain resolves |
| `ip_addresses` | [string] | All resolved IPs |
| `public_ips` | [string] | Public (non-private) IPs |
| `internal_ips` | [string] | Private/bogus IPs |
| `ip_flags` | [atom] | Flags like `:localhost`, `:null_route` |
| `mx_records` | [map] | MX records with priority and server |
| `txt_records` | [string] | TXT records |
| `spf_records` | map | Parsed SPF record analysis |
| `dmarc` | map | DMARC policy |
| `nameservers` | [string] | Name servers |
| `wildcard` | boolean | Whether wildcard DNS is detected |
| `server_response` | map | HTTP HEAD response (status, server, headers) |
| `whois` | map or nil | WHOIS data (registrar, dates) if enabled |
| `content_hash` | map or nil | Content similarity score if enabled |
| `fuzzy` | map | Fuzzy matching scores (jaro_winkler, levenshtein, etc.) |

Results where `wildcard: true` and `public_ips: []` are automatically filtered out.

## Permutation Types

| Kind | Description |
|------|-------------|
| Addition | Append a-z to domain |
| Bitsquatting | Flip one bit in each character |
| Hyphenation | Insert hyphens between characters |
| HyphenationTldBoundary | Hyphenate multi-part TLD boundary |
| Insertion | Insert adjacent keyboard characters |
| Omission | Remove each character |
| Repetition | Double each alphabetic character |
| Replacement | Replace with adjacent keyboard characters |
| Subdomain | Insert dots to create subdomains |
| Transposition | Swap adjacent characters |
| VowelSwap | Replace vowels with other vowels |
| VowelShuffle | Combinatorial vowel replacement |
| DoubleVowelInsertion | Insert vowels between vowel pairs |
| Keyword | Prepend/append common keywords |
| Tld | Replace TLD with all known TLDs |
| FauxTld | TLD-like strings as subdomains |
| Mapped | Character substitutions (l→1, o→0, etc.) |
| Homoglyph | Unicode look-alike character substitution |

## Modules

- `DomainTwistex.Twist` — High-level analysis API
- `DomainTwistex.Permutate` — Pure Elixir permutation generator
- `DomainTwistex.Utils` — Domain validation, fuzzy matching, server checks
- `DomainTwistex.DNS` — DNS resolution (A, CNAME, MX, TXT, NS, DMARC, wildcard)
- `DomainTwistex.SPF` — SPF record parser with provider categorization
- `DomainTwistex.Utils.Whois` — RDAP/WHOIS domain lookups
- `DomainTwistex.Utils.ContentSimilarity` — Content-based phishing detection

## License

BSD-3-Clause

## Acknowledgments

Permutation algorithms inspired by [twistrs](https://github.com/haveibeensquatted/twistrs). This library was originally a Rust NIF wrapper around twistrs and has been rewritten as pure Elixir.