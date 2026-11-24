# Changelog

## v1.1.0

### New

- Added `Compound` permutation kind (on by default via `:compound`) for two-sided `my{brand}{kw}` wrappers and SaaS/recruiting combosquat templates (`on{brand}zendesk`, `{brand}-my-salesforce`, `oktalogin-{brand}`, `lifeat{brand}careers`, etc.).
- Added opt-in `Hosted` permutation kind (`hosted: true`, `:hosted_suffixes`, defaulting to `["pages.dev"]`) for free-hosting / PaaS brand redirector candidates (`connect-pages-{brand}.pages.dev`, `{brand}.pages.dev`, `{brand}-{kw}.pages.dev`).
- Added Cyrillic single-character and capped whole-script IDN homoglyphs (including `U+04CF` palochka and `U+04E9` barred o, controlled by `cyrillic: true`) plus Latin hook look-alikes (`U+0199` and `U+01AD`).
- Added runtime customization options `:keywords`, `:extra_keywords`, `:aliases` (runs short tickers/abbreviations through `Keyword`, `Compound`, and `Hosted` without short-label typo noise), `:keyword_tlds`, and `:keyword_tlds_scope`, plus introspection helpers `Permutate.keywords/0` and `Permutate.priority_keywords/0`.
- Non-`.com` target domains now automatically check `@priority_keywords` against `.com` as well when `:keyword_tlds` is `:default`.
- Added `age_days` to RDAP and WHOIS lookup results (`Whois.parse_age_days/1`).
- Added `:signals` map (`shares_nameservers`, `shares_ips`, `shares_mx`, `redirects_to_original`, `has_mx`, `web_only`) to enriched permutation results and `mix twist` CSV output.
- Added matching CLI flags to `mix twist`: `--extra-keywords`, `--keywords-file`, `--aliases`, `--keyword-tlds`, `--keyword-tlds-priority`, `--no-compound`, `--no-cyrillic`, `--hosted`, and `--hosted-suffixes`.

### Accuracy

- Repaired `si`--`z` truncation in `priv/keywords.txt` and expanded the built-in corpus to 868 sorted keywords covering recruiting/HR lures (`hire`, `hires`, `hiring`, `careers`, `jobs`, `interviews`, `webinar`, `paidexpert`, `lifeat`, etc.), ShinyHunters/Com SSO & IT lures (`sso`, `okta`, `internal`, `ticket`, `passkey`, `salesforce`, `zendesk`, `report`, etc.), and legal pretexts (`legal`, `legaldept`, `dept`, `counsel`, `litigation`, `settlement`, `subpoena`).
- Ensured `@keywords` is always a superset of `@priority_keywords` on default runs.
- Added `career`, `careers`, `jobs`, `claims`, `report`, `legal`, `law`, and `attorney` to `@common_tlds`.
- Retained MX-active hits in `Twist` even when `wildcard: true` and `public_ips: []`.

## v1.0.0

First stable release! The library has been extensively refactored and is now production-ready.

All features from v0.10.0 are included with improved stability and documentation.

## v0.10.0

### Breaking changes

- Modules reorganized under `DomainTwistex.*` (`DomainTwistex.Twist`, `DomainTwistex.DNS`, `DomainTwistex.Whois`, ...); `DomainTwistex` is the public entry point.
- The original domain is no longer included in permutations.
- Homoglyph and other IDN permutations now have an ASCII (punycode) `:fqdn` and a `:unicode` key.
- `server_response` is now `%{http: ..., https: ..., tls: ...}` with integer status codes.
- SPF mechanisms are maps (`%{type:, qualifier:, value:}`) instead of tuples; `all_mechanism` is `nil` when absent.
- `analyze_distributed/2` returns the same map shape as `analyze/2`.
- `vowel_shuffle` is now off by default and capped at 4 vowels; `Tld` permutations use a curated ~150 TLD list by default (`tlds: :all` for the previous behavior).
- Unknown options raise `ArgumentError`.
- WHOIS/RDAP is now on by default (`whois: false` or CLI `--no-whois` to skip). It only runs for registered hits.
- Results are sorted by kind, then name (`ordered: true` keeps permutation order).
- `spf_records` is `nil` when no SPF record is published (was `{:error, reason}`), so results are JSON-encodable as-is.
- Removed: `Utils.generate_permutations/2` (use `DomainTwistex.permutations/2`), `Utils.validate_domain_resolution/2` and `DNS.resolve_ips/2` (use `DNS.probe/2`), `Utils.check_server/2` (use `Utils.check_domain/3` or `HTTP.probe/3`), `Domain.suffixes/0`, `SPF.ProviderCategories.all_providers/0` and `known_domains/0` (use `SPF.list_categories/0`), and the CLI's `-w` alias.

### Accuracy

- IDN permutations are punycode-encoded before DNS/RDAP lookups, so homoglyph domains can actually be found.
- Domains are detected by NOERROR vs NXDOMAIN, so MX-only and parked domains are no longer missed.
- Probe timeouts are retried once and counted in `stats`. A saturated resolver no longer looks like "nothing is registered".
- Default resolvers are Cloudflare, Google, and Quad9 unfiltered, with at most 40 probes in flight per resolver. `nameservers: nil` (CLI `--system-dns`) keeps the system resolver. This default also applies when calling `DomainTwistex.DNS` functions directly.
- Input is normalized (case, URL scheme/path/port, trailing dot) and reduced to its registrable domain via the public suffix list.
- Registry wildcard TLDs are detected and their false positives filtered.
- IP classification covers all of 127/8, 0/8, 169.254/16, 100.64/10, documentation ranges, and IPv6.
- `Mapped` permutations apply at every occurrence; single-character labels no longer crash.
- WHOIS: exact field matching, line-anchored "not registered" detection, RDAP 404 treated as authoritative.
- SPF: qualifiers, `redirect=`, `exists`, `ptr`, bare `a`/`mx`, case-insensitivity, lookup limit and multiple-record warnings.
- Fuzzy scores compare the full name left of the public suffix; adds `tld_changed`.

### Performance

- Two-stage pipeline: one A query per permutation at `dns_concurrency` (default 200), full enrichment only for hits.
- CNAME is read from the A answer instead of a separate query.
- TCP fallback only on truncation or UDP timeout (previously also on NXDOMAIN).
- `:nameservers` option spreads queries across resolvers.
- RDAP bootstrap is fetched once (serialized), indexed by TLD, and failures are cached.
- Defaults are computed at runtime instead of compile time.

### Resilience

- Enrichment runs under a per-domain budget; slow checks produce partial results listed in `:timed_out` instead of dropping the domain.
- `stats` now reports `found`, `resolvable`, `mx`, `wildcard_filtered`, `dns_errors`, and `timeouts`.
- Distributed chunks from failed nodes are re-run locally.
- WHOIS and HTTP responses are size-capped.

### New

- `DomainTwistex.analyze_stream/2` for streaming results.
- The original domain is enriched as a baseline (`:original`) for comparing nameservers, IPs, and MX.
- HTTPS probing with page title, `Location`, and TLS certificate issuer/SANs/age.
- `:kinds`, `:tlds`, `:nameservers`, `:dns_concurrency`, `:dns_timeout`, `:http_timeout`, `:retries` options.
- `mix twist`: `--nameserver`, `--dns-concurrency`, `--dns-timeout`, `--kinds`, `--all-tlds`, `--faux-tld`, `--vowel-shuffle`, `--no-whois`; `--priority-keywords` now works; CSV is properly escaped and includes HTTP/TLS/WHOIS columns.
