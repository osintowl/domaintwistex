defmodule DomainTwistex.Utils do
  @moduledoc """
  Domain validation and enrichment utilities.

  Provides domain checking, IP classification, fuzzy matching, and HTTP/TLS
  checks.
  """

  alias DomainTwistex.{Domain, DNS, HTTP, SPF, Whois}

  @type check_result :: {:ok, map()} | {:error, atom() | String.t()}

  @keyboard_positions [~w(q w e r t y u i o p), ~w(a s d f g h j k l), ~w(z x c v b n m)]
                      |> Enum.with_index()
                      |> Enum.flat_map(fn {row, r} ->
                        Enum.with_index(row, fn key, c -> {key, {r, c}} end)
                      end)
                      |> Map.new()

  @doc """
  Classifies IP tuples into public and internal addresses with flags.

  Returns string-formatted IPs.
  """
  @spec classify_ips([:inet.ip_address()]) :: map()
  def classify_ips(ips) do
    {internal, public} = Enum.split_with(ips, &ip_flag/1)

    %{
      ips: Enum.map(ips, &DNS.ip_to_string/1),
      public_ips: Enum.map(public, &DNS.ip_to_string/1),
      internal_ips: Enum.map(internal, &DNS.ip_to_string/1),
      flags: internal |> Enum.map(&ip_flag/1) |> Enum.uniq()
    }
  end

  @doc """
  Returns a flag atom for non-public IPs, or `nil` for public addresses.

  ## Examples

      iex> DomainTwistex.Utils.ip_flag({10, 0, 0, 1})
      :private_10

      iex> DomainTwistex.Utils.ip_flag({8, 8, 8, 8})
      nil

  """
  @spec ip_flag(:inet.ip_address()) :: atom() | nil
  def ip_flag({127, _, _, _}), do: :localhost
  def ip_flag({0, _, _, _}), do: :null_route
  def ip_flag({10, _, _, _}), do: :private_10
  def ip_flag({172, b, _, _}) when b in 16..31, do: :private_172
  def ip_flag({192, 168, _, _}), do: :private_192
  def ip_flag({169, 254, _, _}), do: :link_local
  def ip_flag({100, b, _, _}) when b in 64..127, do: :cgnat
  def ip_flag({192, 0, 2, _}), do: :documentation
  def ip_flag({198, 51, 100, _}), do: :documentation
  def ip_flag({203, 0, 113, _}), do: :documentation
  def ip_flag({198, b, _, _}) when b in 18..19, do: :benchmark
  def ip_flag({a, _, _, _}) when a >= 224, do: :reserved
  def ip_flag({0, 0, 0, 0, 0, 0, 0, 0}), do: :null_route
  def ip_flag({0, 0, 0, 0, 0, 0, 0, 1}), do: :localhost
  def ip_flag({0, 0, 0, 0, 0, 0xFFFF, hi, lo}), do: ip_flag(v4_from_mapped(hi, lo))
  def ip_flag({a, _, _, _, _, _, _, _}) when a in 0xFC00..0xFDFF, do: :ipv6_ula
  def ip_flag({a, _, _, _, _, _, _, _}) when a in 0xFE80..0xFEBF, do: :link_local
  def ip_flag({a, _, _, _, _, _, _, _}) when a >= 0xFF00, do: :reserved
  def ip_flag({0x2001, 0x0DB8, _, _, _, _, _, _}), do: :documentation
  def ip_flag(_), do: nil

  defp v4_from_mapped(hi, lo), do: {div(hi, 256), rem(hi, 256), div(lo, 256), rem(lo, 256)}

  @doc """
  Checks and enriches a single domain: DNS, HTTP/TLS, WHOIS, and fuzzy scores.

  Convenience wrapper around `DomainTwistex.DNS.probe/2` + `enrich/4`.

  ## Parameters

    * `permutation` - Map containing at least `:fqdn` and `:tld` keys
    * `domain` - Original domain for fuzzy matching comparison
    * `opts` - Keyword list (`:whois`, `:timeout`, `:http_timeout`,
      `:nameservers`, `:dns_timeout`, `:retries`)

  ## Returns

    * `{:ok, map}` - Successfully checked domain with all information
    * `{:error, reason}` - When the domain does not exist or lookup fails

  """
  @spec check_domain(map(), String.t(), keyword()) :: check_result()
  def check_domain(permutation, domain, opts \\ []) do
    case DNS.probe(permutation.fqdn, opts) do
      {:ok, probe} -> {:ok, enrich(permutation, probe, %{domain: domain}, opts)}
      {:error, :nxdomain} -> {:error, :not_resolvable}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Enriches an existing domain with DNS records, HTTP/TLS data, WHOIS (unless
  `whois: false`), and fuzzy similarity scores.

  All lookups run concurrently within a shared `:timeout` budget. Lookups
  that don't finish in time fall back to empty defaults and are listed in
  the result's `:timed_out` field, so a slow server never drops the result.

  `context` is a map with `:domain` (the original domain, used for fuzzy
  scores).
  """
  @spec enrich(map(), DNS.probe_result(), map(), keyword()) :: map()
  def enrich(permutation, probe, context, opts \\ []) do
    fqdn = permutation.fqdn
    budget = Keyword.get(opts, :timeout, 15_000)
    dns_opts = Keyword.take(opts, [:nameservers, :dns_timeout, :retries])
    v4 = classify_ips(probe.ips)

    jobs = [
      {:aaaa, fn -> ok_or(DNS.get_aaaa_records(fqdn, dns_opts), []) end, []},
      {:mx, fn -> ok_or(DNS.get_mx_records(fqdn, dns_opts), []) end, []},
      {:txt, fn -> ok_or(DNS.get_txt_records(fqdn, dns_opts), []) end, []},
      {:dmarc, fn -> ok_or(DNS.check_dmarc(fqdn, dns_opts), %{}) end, %{}},
      {:ns, fn -> ok_or(DNS.get_nameservers(fqdn, dns_opts), []) end, []},
      {:wildcard, fn -> ok_or(DNS.has_wildcard(fqdn, dns_opts), false) end, false},
      {:http, fn -> http_check(fqdn, probe.ips, dns_opts, opts) end, skipped("timeout")}
    ]

    jobs =
      if Keyword.get(opts, :whois, true),
        do: jobs ++ [{:whois, fn -> fetch_whois(fqdn) end, nil}],
        else: jobs

    {results, timed_out} = run_parallel(jobs, budget)

    ips = classify_ips(probe.ips ++ results.aaaa)
    spf = spf_or_nil(results.txt)

    enriched =
      Map.merge(permutation, %{
        registered: true,
        resolvable: ips.ips != [],
        cname: probe.cname,
        ip_addresses: ips.ips,
        public_ips: ips.public_ips,
        internal_ips: ips.internal_ips,
        ip_flags: Enum.uniq(v4.flags ++ ips.flags),
        mx_records: results.mx,
        txt_records: results.txt,
        spf_records: spf,
        dmarc: results.dmarc,
        server_response: results.http,
        nameservers: results.ns,
        wildcard: results.wildcard,
        whois: Map.get(results, :whois),
        fuzzy: calculate_fuzzy_scores(context.domain, Map.get(permutation, :unicode, fqdn)),
        timed_out: timed_out
      })

    Map.put(enriched, :signals, compute_signals(enriched, context))
  end

  @doc """
  Builds a minimal result for a domain that exists but could not be enriched.
  """
  @spec minimal_result(map(), DNS.probe_result(), map()) :: map()
  def minimal_result(permutation, probe, context) do
    ips = classify_ips(probe.ips)

    minimal =
      Map.merge(permutation, %{
        registered: true,
        resolvable: ips.ips != [],
        cname: probe.cname,
        ip_addresses: ips.ips,
        public_ips: ips.public_ips,
        internal_ips: ips.internal_ips,
        ip_flags: ips.flags,
        mx_records: [],
        txt_records: [],
        spf_records: nil,
        dmarc: %{},
        server_response: skipped("enrichment timed out"),
        nameservers: [],
        wildcard: false,
        whois: nil,
        fuzzy:
          calculate_fuzzy_scores(
            context.domain,
            Map.get(permutation, :unicode, permutation.fqdn)
          ),
        timed_out: [:enrichment]
      })

    Map.put(minimal, :signals, compute_signals(minimal, context))
  end

  defp http_check(fqdn, v4_ips, dns_opts, opts) do
    target =
      Enum.find(v4_ips, &(ip_flag(&1) == nil)) ||
        fqdn |> DNS.get_aaaa_records(dns_opts) |> ok_or([]) |> Enum.find(&(ip_flag(&1) == nil))

    if target do
      HTTP.probe(fqdn, target, http_timeout: Keyword.get(opts, :http_timeout, 5_000))
    else
      skipped("no public IPs")
    end
  end

  defp skipped(reason), do: %{status: :skipped, reason: reason}

  # nil instead of {:error, _} so results stay JSON-encodable
  defp spf_or_nil(txt) do
    case SPF.parse_txt_records({:ok, txt}) do
      {:error, _} -> nil
      spf -> spf
    end
  end

  # Runs {key, fun, default} jobs concurrently under one time budget
  defp run_parallel(jobs, budget) do
    tasks =
      Enum.map(jobs, fn {key, fun, default} ->
        {key, default, Task.async(fn -> safe_call(fun, default) end)}
      end)

    tasks
    |> Enum.map(&elem(&1, 2))
    |> Task.yield_many(budget)
    |> Enum.zip(tasks)
    |> Enum.reduce({%{}, []}, fn {{task, reply}, {key, default, _}}, {acc, timed_out} ->
      case reply do
        {:ok, value} ->
          {Map.put(acc, key, value), timed_out}

        _ ->
          Task.shutdown(task, :brutal_kill)
          {Map.put(acc, key, default), [key | timed_out]}
      end
    end)
  end

  defp ok_or({:ok, value}, _default), do: value
  defp ok_or(_, default), do: default

  # Isolates enrichment failures (network libraries can raise or exit on
  # malformed peers) so one bad host never takes down the scan
  defp safe_call(fun, default) do
    fun.()
  rescue
    _ -> default
  catch
    :exit, _ -> default
  end

  defp fetch_whois(fqdn) do
    case Whois.lookup(fqdn) do
      {:ok, data} ->
        %{
          registrar: data[:registrar],
          creation_date: data[:creation_date],
          age_days: data[:age_days],
          expiration_date: data[:expiration_date],
          registered: data[:registered],
          source: data[:source]
        }

      {:error, _} ->
        nil
    end
  end

  @doc """
  Computes deterministic baseline-comparison and posture signals for an enriched hit.

  Returns a map with boolean flags:
    * `:shares_nameservers` - Overlaps with `:original` nameservers
    * `:shares_ips` - Overlaps with `:original` public IPs
    * `:shares_mx` - Overlaps with `:original` MX servers
    * `:redirects_to_original` - HTTP or HTTPS `Location` redirects to `:domain`
    * `:has_mx` - Publishes at least one MX record
    * `:web_only` - Has public IPs with no MX, SPF, or DMARC records

  """
  @spec compute_signals(map(), map()) :: map()
  def compute_signals(hit, context) do
    original = Map.get(context, :original) || %{}
    mx = Map.get(hit, :mx_records, [])
    public_ips = Map.get(hit, :public_ips, [])
    dmarc = Map.get(hit, :dmarc, %{})

    %{
      shares_nameservers:
        overlap?(
          downcase_list(Map.get(hit, :nameservers, [])),
          downcase_list(Map.get(original, :nameservers, []))
        ),
      shares_ips: overlap?(public_ips, Map.get(original, :public_ips, [])),
      shares_mx: overlap?(mx_servers(mx), mx_servers(Map.get(original, :mx_records, []))),
      redirects_to_original:
        redirects_to_domain?(Map.get(hit, :server_response), Map.get(context, :domain)),
      has_mx: mx != [],
      web_only:
        public_ips != [] and mx == [] and Map.get(hit, :spf_records) == nil and
          not valid_dmarc?(dmarc)
    }
  end

  defp overlap?([], _), do: false
  defp overlap?(_, []), do: false
  defp overlap?(a, b), do: not MapSet.disjoint?(MapSet.new(a), MapSet.new(b))

  defp downcase_list(list) when is_list(list), do: Enum.map(list, &String.downcase(to_string(&1)))
  defp downcase_list(_), do: []

  defp mx_servers(records) when is_list(records) do
    for %{server: s} <- records, is_binary(s) and s != "", do: String.downcase(s)
  end

  defp mx_servers(_), do: []

  defp valid_dmarc?(dmarc) when is_map(dmarc),
    do: map_size(dmarc) > 0 and not Map.has_key?(dmarc, :error)

  defp valid_dmarc?(_), do: false

  defp redirects_to_domain?(server_response, target_domain)
       when is_map(server_response) and is_binary(target_domain) and target_domain != "" do
    target_reg = target_domain |> Domain.normalize() |> Domain.registrable()

    [server_response[:http], server_response[:https]]
    |> Enum.any?(fn
      %{location: loc} when is_binary(loc) ->
        trimmed = String.trim(loc)

        if String.match?(trimmed, ~r{^(https?://|//)}i) do
          candidate =
            if String.starts_with?(trimmed, "//"), do: "https:" <> trimmed, else: trimmed

          candidate |> Domain.normalize() |> Domain.registrable() == target_reg
        else
          false
        end

      _ ->
        false
    end)
  end

  defp redirects_to_domain?(_, _), do: false

  # =============================================================================
  # Fuzzy matching
  # =============================================================================

  @doc """
  Calculates multiple fuzzy similarity scores between original and permuted domain.

  Compares the part of each domain left of its public suffix (so
  `ex.ample.com` is compared as `ex.ample` vs `example`).

  Returns a map with:
    * `:jaro_winkler` - Jaro distance of the names (0.0-1.0, higher = more similar)
    * `:levenshtein` - Edit distance (lower = more similar)
    * `:levenshtein_normalized` - Normalized similarity (0.0-1.0, higher = more similar)
    * `:char_diff` - Count of positional character differences
    * `:keyboard_proximity` - Score accounting for keyboard layout
    * `:tld_changed` - Whether the suffix differs from the original

  """
  @spec calculate_fuzzy_scores(String.t(), String.t()) :: map()
  def calculate_fuzzy_scores(original, permuted) do
    orig_name = Domain.stem(original)
    perm_name = Domain.stem(permuted)

    lev = levenshtein_distance(orig_name, perm_name)
    max_len = max(String.length(orig_name), String.length(perm_name))

    %{
      jaro_winkler: String.jaro_distance(orig_name, perm_name),
      levenshtein: lev,
      levenshtein_normalized: if(max_len == 0, do: 1.0, else: 1.0 - lev / max_len),
      char_diff: count_char_differences(orig_name, perm_name),
      keyboard_proximity: keyboard_proximity_score(orig_name, perm_name),
      tld_changed: elem(Domain.split(original), 1) != elem(Domain.split(permuted), 1)
    }
  end

  # Levenshtein edit distance, single-row dynamic programming
  defp levenshtein_distance(s1, s2) do
    a = String.graphemes(s1)
    b = String.graphemes(s2)
    first_row = Enum.to_list(0..length(b))

    a
    |> Enum.with_index(1)
    |> Enum.reduce(first_row, fn {ca, i}, [diag | prev_rest] = _prev ->
      {row, _, _} =
        Enum.reduce(Enum.zip(b, prev_rest), {[i], diag, i}, fn {cb, above}, {row, diag, left} ->
          val = Enum.min([left + 1, above + 1, diag + if(ca == cb, do: 0, else: 1)])
          {[val | row], above, val}
        end)

      Enum.reverse(row)
    end)
    |> List.last()
  end

  defp count_char_differences(s1, s2) do
    chars1 = String.graphemes(s1)
    chars2 = String.graphemes(s2)
    max_len = max(length(chars1), length(chars2))

    padded1 = chars1 ++ List.duplicate("", max_len - length(chars1))
    padded2 = chars2 ++ List.duplicate("", max_len - length(chars2))

    Enum.zip(padded1, padded2)
    |> Enum.count(fn {a, b} -> a != b end)
  end

  # Keyboard proximity score - lower distance for adjacent keys
  defp keyboard_proximity_score(original, permuted) do
    orig_chars = String.graphemes(original)
    perm_chars = String.graphemes(permuted)

    distances =
      Enum.zip_with(orig_chars, perm_chars, fn
        c, c ->
          0.0

        c1, c2 ->
          case {@keyboard_positions[c1], @keyboard_positions[c2]} do
            {{r1, k1}, {r2, k2}} -> :math.sqrt((r1 - r2) ** 2 + (k1 - k2) ** 2) / 5.0
            _ -> 1.0
          end
      end)

    len_diff = abs(length(orig_chars) - length(perm_chars))

    case distances do
      [] -> 0.0
      _ -> max(0.0, 1.0 - Enum.sum(distances) / length(distances) - len_diff * 0.1)
    end
  end
end
