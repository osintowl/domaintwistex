defmodule DomainTwistex.Twist do
  @moduledoc """
  High-level domain analysis functionality combining permutation generation
  with concurrent domain validation checks.

  Analysis runs as a two-stage pipeline:

    1. **Probe** - one A query per permutation separates registered names
       (NOERROR) from unregistered ones (NXDOMAIN). In-flight queries are
       capped per resolver so a stub resolver cannot drop the whole scan.
       Timeouts and SERVFAILs are retried once and are not treated as
       unregistered. Hits whose IPs match their TLD's registry wildcard
       are discarded.
    2. **Enrich** - only hits get the full treatment (AAAA/MX/TXT/DMARC/NS,
       HTTP/TLS, WHOIS) at lower concurrency (`:max_concurrency`),
       each under a `:timeout` budget. Slow lookups produce partial results
       instead of dropping the domain.
  """

  require Logger

  alias DomainTwistex.{Domain, DNS, Permutate, Utils, Whois}

  # A single recursive resolver (a home router, or one anycast address behind
  # one NAT path) starts answering with timeouts once a few dozen queries are
  # in flight, so probes are capped per resolver.
  @max_in_flight_per_resolver 40
  @resolver_down [:timeout, :enetunreach, :econnrefused, :ehostunreach]

  @permutation_keys [
    :tlds,
    :faux_tld,
    :double_vowel,
    :vowel_shuffle,
    :priority_keywords_only,
    :kinds
  ]
  @dns_keys [:nameservers, :dns_timeout, :retries]

  @type analysis_opts :: keyword()

  @type analysis_result :: %{
          domain: String.t(),
          original: map(),
          permutations: [map()],
          stats: %{
            total: non_neg_integer(),
            found: non_neg_integer(),
            resolvable: non_neg_integer(),
            mx: non_neg_integer(),
            wildcard_filtered: non_neg_integer(),
            dns_errors: non_neg_integer(),
            timeouts: non_neg_integer(),
            elapsed_ms: non_neg_integer()
          }
        }

  @doc """
  Returns the default analysis options (computed at runtime).
  """
  @spec default_opts() :: keyword()
  def default_opts do
    [
      max_concurrency: max(System.schedulers_online() * 4, 16),
      dns_concurrency: 200,
      timeout: 15_000,
      dns_timeout: 5_000,
      http_timeout: 5_000,
      retries: 1,
      nameservers: DNS.public_nameservers(),
      ordered: false,
      whois: true,
      tlds: :common,
      faux_tld: false,
      double_vowel: true,
      vowel_shuffle: false,
      priority_keywords_only: false,
      kinds: nil
    ]
  end

  @doc """
  Analyzes a domain by generating permutations and checking them concurrently.

  ## Parameters

    * `domain` - Domain or URL to analyze (e.g., `"example.com"`,
      `"https://mail.example.co.uk/"`). Reduced to its registrable domain.
    * `opts` - Keyword list of options:
      * `:max_concurrency` - Concurrent enrichments (default: max(CPU * 4, 16))
      * `:dns_concurrency` - Concurrent existence probes (default: 200)
      * `:timeout` - Enrichment budget per domain in ms (default: 15_000)
      * `:dns_timeout` - Timeout per DNS query in ms (default: 5_000)
      * `:http_timeout` - Timeout per HTTP/HTTPS request in ms (default: 5_000)
      * `:retries` - DNS retries on timeout/SERVFAIL (default: 1)
      * `:nameservers` - Resolvers to spread queries across (default: Cloudflare,
        Google, and Quad9 unfiltered). `nil` uses the system resolver. In-flight
        probes are capped at 40 per resolver.
      * `:whois` - WHOIS/RDAP lookups for registered hits (default: true).
        `false` is faster.
      * `:ordered` - Return results in permutation order instead of grouped
        by kind (default: false)
      * Permutation options: `:tlds`, `:faux_tld`, `:double_vowel`,
        `:vowel_shuffle`, `:priority_keywords_only`, `:kinds` — see
        `DomainTwistex.Permutate.generate_permutations/2`

  ## Returns

    A map with:
      * `:domain` - The normalized domain
      * `:original` - Resolved baseline data for the original domain
        (compare permutations' nameservers, IPs, and MX against it)
      * `:permutations` - Registered permutations with raw enrichment data
      * `:stats` - Counts for generated, found, resolvable, MX, filtered,
        errors, timeouts, and elapsed time

  """
  @spec analyze_domain(String.t(), analysis_opts()) :: analysis_result()
  def analyze_domain(domain, opts \\ []) do
    start_time = System.monotonic_time(:millisecond)
    {domain, opts} = start(domain, opts)
    context = build_context(domain, opts)
    permutations = Permutate.generate_permutations(domain, Keyword.take(opts, @permutation_keys))

    {results, counters} = run(permutations, context, opts)

    %{
      domain: domain,
      original: context.original,
      permutations: sort_results(results, opts),
      stats: build_stats(length(permutations), results, counters, start_time)
    }
  end

  @doc """
  Streams enriched results as they are found.

  Same options as `analyze_domain/2`. Results arrive in completion order
  (or permutation order with `ordered: true`).

  ## Example

      "example.com"
      |> DomainTwistex.Twist.analyze_stream()
      |> Stream.filter(&(&1.mx_records != []))
      |> Enum.take(10)

  """
  @spec analyze_stream(String.t(), analysis_opts()) :: Enumerable.t()
  def analyze_stream(domain, opts \\ []) do
    opts = validate_opts!(opts)
    domain = normalize(domain)

    # Wrapped so nothing (including the baseline lookup) runs until consumed
    Stream.flat_map([domain], fn domain ->
      opts = maybe_fallback_resolvers(opts, domain)
      context = build_context(domain, opts)

      domain
      |> Permutate.generate_permutations(Keyword.take(opts, @permutation_keys))
      |> events(context, opts)
      |> Stream.flat_map(fn
        {:result, r} -> [r]
        _ -> []
      end)
    end)
  end

  @doc """
  Filters domain analysis results to return only permutations with MX records.

  Useful for identifying potentially malicious domains set up for email operations,
  which could be used for phishing attacks.

  ## Returns

    A map with the same shape as `analyze_domain/2`, but permutations filtered
    to only those with MX records.

  """
  @spec get_live_mx_domains(String.t(), analysis_opts()) :: analysis_result()
  def get_live_mx_domains(domain, opts \\ []) do
    result = analyze_domain(domain, opts)
    %{result | permutations: Enum.filter(result.permutations, &(&1.mx_records != []))}
  end

  # =============================================================================
  # Distributed Scanning
  # =============================================================================

  @doc """
  Returns all permutations for a domain without checking them.

  Accepts the permutation options from `DomainTwistex.Permutate.generate_permutations/2`.
  """
  @spec get_permutations(String.t(), keyword()) :: [map()]
  def get_permutations(domain, opts \\ []) do
    Permutate.generate_permutations(domain, opts)
  end

  @doc """
  Splits permutations into N chunks for distributed processing.

  ## Returns

    List of `{chunk_index, permutations}` tuples (at most `num_chunks`)

  """
  @spec split_for_nodes(String.t(), pos_integer(), keyword()) :: [{non_neg_integer(), [map()]}]
  def split_for_nodes(domain, num_chunks, opts \\ []) when num_chunks > 0 do
    domain
    |> Permutate.generate_permutations(Keyword.take(opts, @permutation_keys))
    |> chunk(num_chunks)
  end

  defp chunk([], _n), do: []

  defp chunk(permutations, n) do
    permutations
    |> Enum.chunk_every(ceil(length(permutations) / n))
    |> Enum.with_index()
    |> Enum.map(fn {chunk, idx} -> {idx, chunk} end)
  end

  @doc """
  Analyzes a specific chunk of permutations.

  Use this on each node to process its assigned chunk.

  ## Parameters

    * `permutations` - List of permutation maps to check
    * `domain` - Original domain (for fuzzy distance)
    * `opts` - Same options as `analyze_domain/2`

  """
  @spec analyze_chunk([map()], String.t(), analysis_opts()) :: [map()]
  def analyze_chunk(permutations, domain, opts \\ []) do
    {domain, opts} = start(domain, opts)
    {results, _counters} = run(permutations, build_context(domain, opts), opts)
    sort_results(results, opts)
  end

  @doc false
  # Remote entry point for analyze_distributed/2: takes a prebuilt context
  # so each node doesn't re-resolve the original domain
  def __run_chunk__(permutations, context, opts), do: run(permutations, context, opts)

  @doc """
  Distributes analysis across connected Erlang nodes.

  Splits work across all connected nodes + current node. If a node fails,
  its chunk is re-run locally.

  ## Parameters

    * `domain` - Domain to analyze
    * `opts` - Options:
      * `:nodes` - List of nodes to use (default: `[node() | Node.list()]`)
      * All other options from `analyze_domain/2`

  ## Returns

    Same shape as `analyze_domain/2`

  """
  @spec analyze_distributed(String.t(), keyword()) :: analysis_result()
  def analyze_distributed(domain, opts \\ []) do
    start_time = System.monotonic_time(:millisecond)
    nodes = Keyword.get(opts, :nodes, [node() | Node.list()])

    if nodes == [] do
      raise ArgumentError, "No nodes available for distributed analysis"
    end

    {domain, opts} = start(domain, Keyword.delete(opts, :nodes))
    context = build_context(domain, opts)
    permutations = Permutate.generate_permutations(domain, Keyword.take(opts, @permutation_keys))

    {results, counters} =
      permutations
      |> chunk(length(nodes))
      |> Enum.zip(nodes)
      |> Task.async_stream(
        fn {{_idx, perms}, target} ->
          try do
            :erpc.call(target, __MODULE__, :__run_chunk__, [perms, context, opts], :infinity)
          catch
            _, _ -> run(perms, context, opts)
          end
        end,
        timeout: :infinity,
        ordered: false
      )
      |> Enum.reduce({[], %{}}, fn {:ok, {r, c}}, {results, counters} ->
        {r ++ results, Map.merge(counters, c, fn _k, a, b -> a + b end)}
      end)

    %{
      domain: domain,
      original: context.original,
      permutations: sort_results(results, opts),
      stats: build_stats(length(permutations), results, counters, start_time)
    }
  end

  @doc """
  Returns info about the current distributed setup.
  """
  @spec cluster_info() :: %{
          current_node: node(),
          connected_nodes: [node()],
          total_nodes: non_neg_integer()
        }
  def cluster_info do
    %{
      current_node: node(),
      connected_nodes: Node.list(),
      total_nodes: length(Node.list()) + 1
    }
  end

  # =============================================================================
  # Pipeline
  # =============================================================================

  defp start(domain, opts) do
    opts = validate_opts!(opts)
    domain = normalize(domain)
    {domain, maybe_fallback_resolvers(opts, domain)}
  end

  # The built-in pool is unusable on networks that block outbound DNS.
  # Fall back to the system resolver rather than timing out every name.
  defp maybe_fallback_resolvers(opts, domain) do
    if opts[:nameservers] == DNS.public_nameservers() and pool_unreachable?(opts, domain) do
      Logger.warning(
        "public DNS resolvers unreachable; using the system resolver " <>
          "with at most #{@max_in_flight_per_resolver} probes in flight"
      )

      opts
      |> Keyword.put(:nameservers, nil)
      |> Keyword.update!(:dns_concurrency, &min(&1, @max_in_flight_per_resolver))
    else
      opts
    end
  end

  defp pool_unreachable?(opts, domain) do
    dns_opts =
      opts
      |> Keyword.merge(dns_timeout: 2_000, retries: 1)
      |> Keyword.take(@dns_keys)

    case DNS.probe(domain, dns_opts) do
      {:error, reason} when reason in @resolver_down ->
        match?(
          {:error, reason} when reason in @resolver_down,
          DNS.probe("one.one.one.one", dns_opts)
        )

      _ ->
        false
    end
  end

  defp normalize(domain), do: domain |> Domain.normalize() |> Domain.registrable()

  defp validate_opts!(opts) do
    opts = Keyword.validate!(opts, default_opts())

    # Fail fast on malformed resolvers rather than inside every task
    _ = DNS.parse_nameservers(opts[:nameservers])
    opts
  end

  # Resolves the original domain as a baseline, so callers can compare
  # permutations' nameservers, IPs, and MX against it
  defp build_context(domain, opts) do
    if opts[:whois], do: Whois.prefetch_bootstrap()

    dns_opts = Keyword.take(opts, @dns_keys)
    ascii = DomainTwistex.IDNA.to_ascii(domain)
    {_name, tld} = Domain.split(domain)
    base = %{fqdn: ascii, tld: tld}
    context = %{domain: ascii}

    original =
      case DNS.probe(ascii, dns_opts) do
        {:ok, probe} ->
          base |> Utils.enrich(probe, context, opts) |> Map.delete(:fuzzy)

        {:error, :nxdomain} ->
          Map.merge(base, %{registered: false, resolvable: false})

        {:error, _} ->
          preflight!(dns_opts)
          Map.merge(base, %{registered: false, resolvable: false})
      end

    Map.put(context, :original, original)
  end

  # A random .com name must come back NXDOMAIN; anything else means the
  # resolver is broken and every probe in the scan would just time out
  defp preflight!(dns_opts) do
    label = "dtx-preflight-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    case DNS.probe(label <> ".com", dns_opts) do
      {:error, :nxdomain} ->
        :ok

      {:ok, _} ->
        :ok

      {:error, reason} ->
        raise DomainTwistex.ResolverError, reason: reason, nameservers: dns_opts[:nameservers]
    end
  end

  defp run(permutations, context, opts) do
    permutations
    |> events(context, opts)
    |> Enum.reduce({[], %{}}, fn
      {:result, r}, {results, counters} -> {[r | results], counters}
      {:skip, reason}, {results, counters} -> {results, count_skip(counters, reason)}
    end)
    |> then(fn {results, counters} -> {Enum.reverse(results), counters} end)
  end

  @doc false
  # DNS timeouts count toward both `dns_errors` and `timeouts` in stats
  def count_skip(counters, {:dns_error, :timeout}) do
    counters
    |> Map.update(:dns_error, 1, &(&1 + 1))
    |> Map.update(:timeout, 1, &(&1 + 1))
  end

  def count_skip(counters, {:dns_error, _reason}) do
    Map.update(counters, :dns_error, 1, &(&1 + 1))
  end

  def count_skip(counters, reason) when is_atom(reason) do
    Map.update(counters, reason, 1, &(&1 + 1))
  end

  @doc false
  def dns_probe_concurrency(opts) do
    requested = Keyword.get(opts, :dns_concurrency, 200)

    servers =
      case Keyword.get(opts, :nameservers, :default) do
        :default -> length(DNS.public_nameservers())
        nil -> 1
        [] -> 1
        list when is_list(list) -> max(length(list), 1)
      end

    min(requested, servers * @max_in_flight_per_resolver)
  end

  # Emits {:result, map} | {:skip, :nxdomain | :wildcard | {:dns_error, reason}}
  defp events(permutations, context, opts) do
    Stream.resource(
      fn ->
        %{
          phase: :primary,
          queue: permutations,
          failed: [],
          wildcards: %{},
          conc: max(dns_probe_concurrency(opts), 1),
          dns_opts: Keyword.take(opts, @dns_keys),
          task_timeout: probe_task_timeout(opts),
          ordered: opts[:ordered]
        }
      end,
      &next_probe/1,
      fn _ -> :ok end
    )
    |> enrich_hits(context, opts)
  end

  defp probe_task_timeout(opts) do
    (opts[:dns_timeout] + 500) * 2 * (opts[:retries] + 1)
  end

  defp next_probe(%{queue: [], phase: :primary, failed: failed} = state) when failed != [] do
    if length(failed) >= 25 do
      Logger.warning("retrying #{length(failed)} DNS probes that timed out or failed")
    end

    state
    |> Map.merge(%{
      phase: :retry,
      queue: Enum.map(failed, fn {perm, _reason} -> perm end),
      failed: [],
      conc: max(div(state.conc, 4), 8)
    })
    |> next_probe()
  end

  defp next_probe(%{queue: []} = state), do: {:halt, state}

  defp next_probe(state) do
    {wave, rest} = Enum.split(state.queue, state.conc)
    {events, failed, wildcards} = probe_wave(wave, state)

    events =
      if state.phase == :retry do
        events ++ Enum.map(failed, fn {_perm, reason} -> {:skip, {:dns_error, reason}} end)
      else
        events
      end

    failed = if state.phase == :primary, do: failed ++ state.failed, else: state.failed
    {events, %{state | queue: rest, failed: failed, wildcards: wildcards}}
  end

  defp probe_wave(wave, state) do
    {events, failed, wildcards} =
      wave
      |> Task.async_stream(&{&1, DNS.probe(&1.fqdn, state.dns_opts)},
        max_concurrency: state.conc,
        timeout: state.task_timeout,
        on_timeout: :kill_task,
        ordered: state.ordered,
        zip_input_on_exit: true
      )
      |> Enum.reduce({[], [], state.wildcards}, &classify_probe(&1, &2, state.dns_opts))

    {Enum.reverse(events), failed, wildcards}
  end

  defp classify_probe({:ok, {perm, {:ok, probe}}}, {events, failed, wildcards}, dns_opts) do
    {set, wildcards} = wildcard_set(wildcards, perm.tld, dns_opts)

    event =
      if probe.ips != [] and MapSet.size(set) > 0 and
           Enum.all?(probe.ips, &MapSet.member?(set, &1)) do
        {:skip, :wildcard}
      else
        {:hit, perm, probe}
      end

    {[event | events], failed, wildcards}
  end

  defp classify_probe({:ok, {_perm, {:error, :nxdomain}}}, {events, failed, wildcards}, _dns_opts) do
    {[{:skip, :nxdomain} | events], failed, wildcards}
  end

  defp classify_probe({:ok, {perm, {:error, reason}}}, {events, failed, wildcards}, _dns_opts) do
    {events, [{perm, reason} | failed], wildcards}
  end

  # zip_input_on_exit: true, so an exit always carries its permutation
  defp classify_probe({:exit, {perm, _reason}}, {events, failed, wildcards}, _dns_opts) do
    {events, [{perm, :timeout} | failed], wildcards}
  end

  # Registry wildcard IPs per TLD, probed lazily only for TLDs with hits
  defp wildcard_set(cache, tld, dns_opts) do
    case cache do
      %{^tld => set} ->
        {set, cache}

      _ ->
        set = DNS.wildcard_ips(tld, dns_opts)
        {set, Map.put(cache, tld, set)}
    end
  end

  defp enrich_hits(events, context, opts) do
    events
    |> Task.async_stream(
      fn
        {:hit, perm, probe} -> {:result, Utils.enrich(perm, probe, context, opts)}
        skip -> skip
      end,
      max_concurrency: opts[:max_concurrency],
      timeout: opts[:timeout] + 5_000,
      on_timeout: :kill_task,
      ordered: opts[:ordered],
      zip_input_on_exit: true
    )
    |> Stream.map(fn
      {:ok, {:result, result}} ->
        if result.wildcard and result.public_ips == [],
          do: {:skip, :wildcard},
          else: {:result, result}

      {:ok, skip} ->
        skip

      {:exit, {{:hit, perm, probe}, _reason}} ->
        {:result, Utils.minimal_result(perm, probe, context)}

      {:exit, {skip, _reason}} ->
        skip
    end)
  end

  # Deterministic output: permutation order with `ordered: true`, otherwise
  # grouped by kind
  defp sort_results(results, opts) do
    if opts[:ordered], do: results, else: Enum.sort_by(results, &{&1.kind, &1.fqdn})
  end

  defp build_stats(total, results, counters, start_time) do
    %{
      total: total,
      found: length(results),
      resolvable: Enum.count(results, & &1.resolvable),
      mx: Enum.count(results, &(&1.mx_records != [])),
      wildcard_filtered: Map.get(counters, :wildcard, 0),
      dns_errors: Map.get(counters, :dns_error, 0),
      timeouts: Map.get(counters, :timeout, 0) + Enum.count(results, &(&1.timed_out != [])),
      elapsed_ms: System.monotonic_time(:millisecond) - start_time
    }
  end
end
