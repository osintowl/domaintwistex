defmodule DomainTwistex do
  @moduledoc """
  Domain permutation and typosquatting detection library.

  DomainTwistex generates domain permutations using 18 different algorithms,
  checks which ones are registered with a fast two-stage DNS pipeline, and
  enriches hits with MX/SPF/DMARC, HTTP/TLS, WHOIS/RDAP data, and fuzzy
  similarity. Results are raw data, left for an analyst (or model) to judge.

  ## Quick Start

      # Analyze a domain (or URL) for typosquatting
      result = DomainTwistex.analyze("example.com")

      # Get only domains with MX records (potential phishing)
      result = DomainTwistex.analyze_mx("example.com")

      # Stream results as they are found
      DomainTwistex.analyze_stream("example.com") |> Enum.take(5)

      # Just generate permutations without checking
      perms = DomainTwistex.permutations("example.com")

  ## Options

  All analysis functions accept these options:

    * `:max_concurrency` - Concurrent enrichments (default: max(CPU * 4, 16))
    * `:dns_concurrency` - Concurrent existence probes (default: 200)
    * `:timeout` - Enrichment budget per domain in ms (default: 15_000)
    * `:dns_timeout` - Timeout per DNS query in ms (default: 5_000)
    * `:nameservers` - Resolvers to spread queries across. Default is Cloudflare,
      Google, and Quad9 unfiltered. `nil` uses the system resolver. Probes are
      capped at 40 in flight per resolver, and timeouts are retried once.
    * `:whois` - WHOIS/RDAP lookups for registered hits (default: true; `false` is faster)
    * `:ordered` - Return results in permutation order (default: grouped by kind)
    * `:tlds` - `:common` (default), `:all`, or a list of TLDs for `Tld` permutations
    * `:kinds` - Only generate these permutation kinds, e.g. `[:homoglyph, :bitsquatting]`

  See `DomainTwistex.Twist.analyze_domain/2` for the full list.

  ## Permutation Types

  The library generates 18 types of domain permutations:

    * Addition - Appending characters (examplea.com)
    * Bitsquatting - Single bit flips (axample.com)
    * Homoglyph - Visually similar characters (exаmple.com, punycode-encoded)
    * Hyphenation - Adding hyphens (ex-ample.com)
    * Insertion - Keyboard-adjacent insertions (exsample.com)
    * Omission - Removing characters (examle.com)
    * Repetition - Repeating characters (exxample.com)
    * Replacement - Keyboard-adjacent replacements (ezample.com)
    * Subdomain - Adding dots (ex.ample.com)
    * Transposition - Swapping adjacent characters (exmaple.com)
    * VowelSwap - Replacing vowels (exomple.com)
    * TLD - Different TLDs (example.net, example.co.uk)
    * And more - see `DomainTwistex.Permutate`

  """

  alias DomainTwistex.Twist

  @type analysis_result :: Twist.analysis_result()

  @type permutation :: DomainTwistex.Permutate.permutation()

  @doc """
  Analyzes a domain by generating permutations and checking them concurrently.

  Returns a map with the original domain info, all registered permutations
  with their raw enrichment data, and statistics about the scan.

  ## Examples

      result = DomainTwistex.analyze("example.com")
      result.stats.total
      #=> 3312

      # Look-alikes that can receive mail and don't share the original's nameservers
      Enum.filter(result.permutations, fn p ->
        p.mx_records != [] and MapSet.disjoint?(MapSet.new(p.nameservers), MapSet.new(result.original[:nameservers] || []))
      end)

      # Without WHOIS (faster) and with explicit resolvers
      DomainTwistex.analyze("example.com", whois: false, nameservers: ["1.1.1.1", "8.8.8.8"])

  """
  @spec analyze(String.t(), keyword()) :: analysis_result()
  defdelegate analyze(domain, opts \\ []), to: Twist, as: :analyze_domain

  @doc """
  Streams enriched permutation results as they are found.

  Accepts the same options as `analyze/2`. Results are not sorted.
  """
  @spec analyze_stream(String.t(), keyword()) :: Enumerable.t()
  defdelegate analyze_stream(domain, opts \\ []), to: Twist

  @doc """
  Analyzes a domain and returns only permutations with MX records.

  This is particularly useful for identifying potential phishing domains
  that are set up to receive or send email.

  ## Examples

      result = DomainTwistex.analyze_mx("google.com")
      Enum.all?(result.permutations, &(&1.mx_records != []))
      #=> true

  """
  @spec analyze_mx(String.t(), keyword()) :: analysis_result()
  defdelegate analyze_mx(domain, opts \\ []), to: Twist, as: :get_live_mx_domains

  @doc """
  Generates all permutations for a domain without checking them.

  Accepts the permutation options from `DomainTwistex.Permutate.generate_permutations/2`.

  ## Examples

      iex> perms = DomainTwistex.permutations("example.com", kinds: [:transposition])
      iex> "exmaple.com" in Enum.map(perms, & &1.fqdn)
      true

  """
  @spec permutations(String.t(), keyword()) :: [permutation()]
  defdelegate permutations(domain, opts \\ []), to: Twist, as: :get_permutations

  @doc """
  Returns information about the current distributed cluster setup.

  ## Examples

      DomainTwistex.cluster_info()
      #=> %{current_node: :nonode@nohost, connected_nodes: [], total_nodes: 1}

  """
  @spec cluster_info() :: %{
          current_node: node(),
          connected_nodes: [node()],
          total_nodes: non_neg_integer()
        }
  defdelegate cluster_info(), to: Twist

  @doc """
  Analyzes a domain across multiple connected Erlang nodes.

  Splits work across all connected nodes and returns the same shape as
  `analyze/2`. Chunks from failed nodes are re-run locally.

  ## Examples

      Node.connect(:"node2@192.168.1.10")
      result = DomainTwistex.analyze_distributed("example.com")

  """
  @spec analyze_distributed(String.t(), keyword()) :: analysis_result()
  defdelegate analyze_distributed(domain, opts \\ []), to: Twist
end
