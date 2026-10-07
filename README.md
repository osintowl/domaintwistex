# DomainTwistex

DomainTwistex is a pure Elixir library for domain name permutation generation and typosquatting detection. It generates domain permutations, finds the registered ones with a fast two-stage DNS pipeline, and enriches each hit with DNS, HTTP/TLS, and WHOIS data. It returns raw data and leaves the judgment of what's malicious to an analyst or model.

## Features

- **18 permutation algorithms** — Addition, Bitsquatting, Hyphenation, HyphenationTldBoundary, Insertion, Omission, Repetition, Replacement, Subdomain, Transposition, VowelSwap, VowelShuffle, DoubleVowelInsertion, Keyword, TLD, FauxTLD, Mapped, and Homoglyph
- **IDN-aware** — homoglyph permutations are punycode-encoded (`xn--`) so they actually resolve; the Unicode form is kept for display
- **Public-suffix aware** — `https://mail.example.co.uk/login` is analyzed as `example.co.uk`
- **Two-stage scanning** — one cheap A query per permutation at high concurrency, full enrichment only for registered names
- **Registered, not just resolving** — NOERROR vs NXDOMAIN detection finds MX-only and parked domains, not only ones with A records
- **Registry wildcard filtering** — discards hits that only resolve because their TLD answers for every name
- **DNS enrichment** — A/AAAA/CNAME/MX/TXT/DMARC/NS/wildcard with EDNS0, TCP fallback on truncation, retries, and custom resolvers
- **HTTP/TLS probing** — status, `Server`, `Location`, page title, and certificate issuer/SANs/age over HTTP and HTTPS
- **WHOIS/RDAP enrichment** — registrar and date lookups via RDAP-first, WHOIS-fallback (on by default)
- **Baseline comparison data** — the original domain is enriched too, so you can compare nameservers, IPs, and MX
- **Fuzzy matching scores** — Jaro, Levenshtein, character diff, keyboard proximity
- **SPF record parsing** — full RFC 7208 terms, lookup counting, warnings, and provider categorization
- **Partial results** — slow lookups never drop a domain; timed-out checks are reported per result
- **Streaming and distributed scanning** — `analyze_stream/2`, or split work across Erlang nodes
- **CLI task** — `mix twist` for command-line scanning

## Installation

Add `domaintwistex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:domaintwistex, "~> 0.10.0"}
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
# Full analysis — resolves original + all permutations
result = DomainTwistex.analyze("example.com")

# Returns:
%{
  domain: "example.com",
  original: %{fqdn: "example.com", resolvable: true, nameservers: [...], ...},
  permutations: [
    %{
      kind: "Homoglyph",
      fqdn: "xn--exmple-jta.com",
      unicode: "exàmple.com",
      registered: true,
      resolvable: true,
      mx_records: [%{priority: 10, server: "mail.xn--exmple-jta.com"}],
      server_response: %{http: %{...}, https: %{status_code: 200, title: "Sign in"}, tls: %{age_days: 3, ...}},
      whois: %{registrar: "...", creation_date: "2026-10-01T...", ...},
      timed_out: [],
      ...
    },
    ...
  ],
  stats: %{
    total: 3312, found: 42, resolvable: 37, mx: 12,
    wildcard_filtered: 5, dns_errors: 0, timeouts: 1, elapsed_ms: 9_876
  }
}

# With options
result = DomainTwistex.analyze("example.com",
  nameservers: ["1.1.1.1", "8.8.8.8"],
  dns_concurrency: 500,
  whois: false,
  kinds: [:homoglyph, :bitsquatting, :tld]
)
```

### Streaming

```elixir
"example.com"
|> DomainTwistex.analyze_stream()
|> Stream.filter(&(&1.mx_records != []))
|> Enum.each(&notify/1)
```

### MX-Only Filter

```elixir
# Returns only permutations with MX records (potential phishing)
result = DomainTwistex.analyze_mx("example.com")
```

### Permutation Generation (No Resolution)

```elixir
permutations = DomainTwistex.permutations("example.com")
# => [%{fqdn: "examplea.com", tld: "com", kind: "Addition"}, ...]

permutations = DomainTwistex.permutations("example.com", tlds: :all, faux_tld: true)
```

### Distributed Scanning

```elixir
Node.connect(:"node2@host")
result = DomainTwistex.analyze_distributed("example.com")
# Same shape as analyze/2; chunks from failed nodes are re-run locally
```

### CLI

```bash
mix twist example.com
mix twist -c 100 --no-whois example.com
mix twist -n 1.1.1.1 -n 8.8.8.8 --dns-concurrency 500 example.com
mix twist --format json -o results.json example.com
mix twist -k homoglyph,bitsquatting example.com
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_concurrency` | `max(System.schedulers_online() * 4, 16)` | Concurrent enrichments (stage 2) |
| `dns_concurrency` | `200` | Concurrent existence probes (stage 1) |
| `timeout` | `15000` | Enrichment budget per domain (ms) |
| `dns_timeout` | `5000` | Timeout per DNS query (ms) |
| `http_timeout` | `5000` | Timeout per HTTP/HTTPS request (ms) |
| `retries` | `1` | DNS retries on timeout/SERVFAIL |
| `nameservers` | Cloudflare, Google, Quad9 unfiltered | `nil` uses the system resolver. 40 in-flight probes per resolver |
| `whois` | `true` | WHOIS/RDAP lookups for registered hits (`false` is faster) |
| `ordered` | `false` | Return results in permutation order instead of grouped by kind |

### Permutation Options

| Option | Default | Description |
|--------|---------|-------------|
| `tlds` | `:common` | `:common` (~150 curated), `:all` (~7K public suffixes), or a list |
| `kinds` | all | Only these kinds, e.g. `[:homoglyph, "Tld"]` |
| `faux_tld` | `false` | Include FauxTld permutations |
| `double_vowel` | `true` | Include DoubleVowelInsertion |
| `vowel_shuffle` | `false` | Include VowelShuffle (up to 625 entries) |
| `priority_keywords_only` | `false` | Only use high-value phishing keywords |

## Inspection Results

Each permutation result includes:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Permutation type (e.g., "Homoglyph", "Tld") |
| `fqdn` | string | ASCII domain name (punycode for IDNs) |
| `unicode` | string | Unicode form, only present for IDN permutations |
| `tld` | string | Public suffix |
| `registered` | boolean | Domain exists in DNS (NOERROR) |
| `resolvable` | boolean | Domain has A/AAAA records |
| `cname` | string or nil | CNAME target |
| `ip_addresses` | [string] | All resolved IPv4/IPv6 addresses |
| `public_ips` | [string] | Public addresses |
| `internal_ips` | [string] | Private/reserved addresses |
| `ip_flags` | [atom] | Flags like `:localhost`, `:private_10`, `:cgnat`, `:ipv6_ula` |
| `mx_records` | [map] | MX records sorted by priority |
| `txt_records` | [string] | TXT records |
| `spf_records` | map or nil | Parsed SPF (mechanisms, lookup count, providers, warnings); nil if none published |
| `dmarc` | map | DMARC policy |
| `nameservers` | [string] | Name servers |
| `wildcard` | boolean | Whether wildcard DNS is configured under the domain |
| `server_response` | map | `%{http: ..., https: ..., tls: ...}` — status, server, location, title, certificate |
| `whois` | map or nil | WHOIS data (registrar, dates); nil if disabled or the lookup failed |
| `fuzzy` | map | Similarity scores |
| `timed_out` | [atom] | Checks that didn't finish within the budget |

Results where `wildcard: true` and `public_ips: []` are filtered out, as are hits whose IPs match their TLD's registry wildcard.

## Permutation Types

| Kind | Description |
|------|-------------|
| Addition | Append a-z to domain |
| Bitsquatting | Flip one bit in each character |
| Hyphenation | Insert hyphens between characters |
| HyphenationTldBoundary | Hyphenate multi-part TLD boundary |
| Insertion | Insert adjacent keyboard characters |
| Omission | Remove each character |
| Repetition | Double each character |
| Replacement | Replace with adjacent keyboard characters |
| Subdomain | Insert dots to create subdomains |
| Transposition | Swap adjacent characters |
| VowelSwap | Replace vowels with other vowels |
| VowelShuffle | Combinatorial vowel replacement (opt-in) |
| DoubleVowelInsertion | Insert vowels between vowel pairs |
| Keyword | Prepend/append common keywords |
| Tld | Replace TLD with common (or all) TLDs |
| FauxTld | TLD-like strings appended to the name (opt-in) |
| Mapped | Character substitutions (l→1, o→0, etc.) at each occurrence |
| Homoglyph | Unicode look-alike character substitution |

## Modules

- `DomainTwistex` — Public API
- `DomainTwistex.Twist` — Analysis pipeline
- `DomainTwistex.Permutate` — Permutation generator
- `DomainTwistex.Domain` — Normalization and public suffix parsing
- `DomainTwistex.IDNA` — Punycode encoding
- `DomainTwistex.DNS` — DNS resolution
- `DomainTwistex.HTTP` — HTTP/HTTPS and TLS certificate probing
- `DomainTwistex.Utils` — Enrichment, IP classification, fuzzy matching
- `DomainTwistex.SPF` — SPF record parser with provider categorization
- `DomainTwistex.Whois` — RDAP/WHOIS domain lookups
- `DomainTwistex.ResolverError` — Raised when the configured resolvers don't answer at all

## License

BSD-3-Clause

## Acknowledgments

Permutation algorithms inspired by [twistrs](https://github.com/haveibeensquatted/twistrs). This library was originally a Rust NIF wrapper around twistrs and has been rewritten as pure Elixir.
