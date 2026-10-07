defmodule DomainTwistex.DNS do
  @moduledoc """
  Pure DNS query operations for domain names.

  Handles A, AAAA, CNAME, MX, TXT, NS, and DMARC record lookups using Erlang's
  `:inet_res` module. All queries use plain UDP (EDNS0 for TXT only, with a
  plain-DNS retry if the resolver rejects it) and only fall back to TCP when
  a response is truncated.

  ## Options

  Every lookup function accepts an optional keyword list:

    * `:nameservers` - Resolvers to use, as IP strings (`"1.1.1.1"`), IP tuples,
      or `{ip, port}` tuples. Queries are spread across them by name hash.
      Defaults to `public_nameservers/0`; pass `nil` to use the system resolver.
    * `:dns_timeout` - Timeout per query in milliseconds (default: 5_000)
    * `:retries` - Extra attempts on timeout/SERVFAIL (default: 1)
  """

  @default_timeout 5_000

  # Unfiltered resolvers only. Filtering services (Quad9 9.9.9.9, Cloudflare
  # 1.1.1.2, OpenDNS) answer NXDOMAIN for names they dislike, which a
  # typosquatting scan would report as unregistered.
  @public_nameservers ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.10"]

  @type ip :: :inet.ip_address()
  @type dns_result(t) :: {:ok, t} | {:error, atom() | String.t()}

  @type probe_result :: %{
          ips: [ip()],
          cname: String.t() | nil
        }

  @doc """
  Single-query existence check for a domain.

  Sends one A query and distinguishes NXDOMAIN (does not exist) from NOERROR
  (exists, possibly with no A records). CNAMEs come back in the same answer,
  so no separate CNAME query is needed.

  ## Returns

    * `{:ok, %{ips: [ip_tuple], cname: String.t() | nil}}` - domain exists
    * `{:error, :nxdomain}` - domain does not exist
    * `{:error, reason}` - lookup failed (`:timeout`, `:servfail`, ...)

  """
  @spec probe(String.t(), keyword()) :: {:ok, probe_result()} | {:error, atom()}
  def probe(domain, opts \\ []) do
    case query(domain, :a, opts) do
      {:ok, msg} ->
        answers = :inet_dns.msg(msg, :anlist)

        {:ok,
         %{
           ips: rr_data(answers, :a),
           cname:
             case rr_data(answers, :cname) do
               [c | _] -> c |> to_string() |> String.trim_trailing(".")
               [] -> nil
             end
         }}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Retrieves IPv6 (AAAA) addresses for a domain as IP tuples.
  """
  @spec get_aaaa_records(String.t(), keyword()) :: dns_result([ip()])
  def get_aaaa_records(domain, opts \\ []) do
    with {:ok, msg} <- query(domain, :aaaa, opts) do
      {:ok, msg |> :inet_dns.msg(:anlist) |> rr_data(:aaaa)}
    end
  end

  @doc """
  Retrieves nameserver (NS) records for a domain.

  ## Returns

    * `{:ok, [String.t()]}` - List of nameserver hostnames
    * `{:error, reason}` on failure

  """
  @spec get_nameservers(String.t(), keyword()) :: dns_result([String.t()])
  def get_nameservers(domain, opts \\ []) do
    case query(domain, :ns, opts) do
      {:ok, msg} ->
        case msg |> :inet_dns.msg(:anlist) |> rr_data(:ns) do
          [] ->
            {:error, "No nameservers found"}

          ns ->
            {:ok,
             Enum.map(ns, &(&1 |> to_string() |> String.trim_trailing(".") |> String.downcase()))}
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Retrieves MX (Mail Exchange) records for a domain, sorted by priority.

  ## Returns

    * `{:ok, [%{priority: integer(), server: String.t()}]}` on success
    * `{:error, reason}` on failure

  """
  @spec get_mx_records(String.t(), keyword()) ::
          dns_result([%{priority: integer(), server: String.t()}])
  def get_mx_records(domain, opts \\ []) do
    case query(domain, :mx, opts) do
      {:ok, msg} ->
        records =
          msg
          |> :inet_dns.msg(:anlist)
          |> rr_data(:mx)
          |> Enum.map(fn {priority, server} ->
            %{priority: priority, server: server |> to_string() |> String.trim_trailing(".")}
          end)
          |> Enum.sort_by(& &1.priority)

        {:ok, records}

      {:error, :nxdomain} ->
        {:ok, []}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Retrieves TXT records for a domain.

  Multi-string TXT records are concatenated per RFC 7208.

  ## Returns

    * `{:ok, [String.t()]}` - List of TXT record strings
    * `{:error, reason}` on failure

  """
  @spec get_txt_records(String.t(), keyword()) :: dns_result([String.t()])
  def get_txt_records(domain, opts \\ []) do
    case query(domain, :txt, opts) do
      {:ok, msg} ->
        {:ok, msg |> :inet_dns.msg(:anlist) |> rr_data(:txt) |> Enum.map(&txt_to_string/1)}

      {:error, :nxdomain} ->
        {:ok, []}

      {:error, reason} ->
        {:error, "Failed to retrieve TXT records: #{inspect(reason)}"}
    end
  end

  @doc """
  Detects if a domain has wildcard DNS configured.

  Queries a random non-existent subdomain - if it resolves, wildcard is active.

  ## Returns

    * `{:ok, boolean}` - true if wildcard DNS detected

  """
  @spec has_wildcard(String.t(), keyword()) :: dns_result(boolean())
  def has_wildcard(domain, opts \\ []) do
    case probe(random_label() <> "." <> domain, opts) do
      {:ok, %{ips: [_ | _]}} -> {:ok, true}
      _ -> {:ok, false}
    end
  end

  @doc """
  Returns the set of IPs a random name under `suffix` resolves to.

  Used to detect registry-level wildcards (TLDs that answer for every name).
  Returns an empty `MapSet` when the suffix has no wildcard.
  """
  @spec wildcard_ips(String.t(), keyword()) :: MapSet.t(ip())
  def wildcard_ips(suffix, opts \\ []) do
    case probe(random_label() <> "." <> suffix, opts) do
      {:ok, %{ips: ips}} -> MapSet.new(ips)
      _ -> MapSet.new()
    end
  end

  @doc """
  Checks DMARC records for a domain.

  ## Returns

    * `{:ok, map}` - Parsed DMARC policy or error info

  """
  @spec check_dmarc(String.t(), keyword()) :: dns_result(map())
  def check_dmarc(domain, opts \\ []) do
    case query("_dmarc." <> domain, :txt, opts) do
      {:ok, msg} ->
        msg
        |> :inet_dns.msg(:anlist)
        |> rr_data(:txt)
        |> Enum.map(&txt_to_string/1)
        |> Enum.filter(&String.starts_with?(String.downcase(&1), "v=dmarc1"))
        |> case do
          [] -> {:ok, %{error: "No valid DMARC record found"}}
          [record | _] -> {:ok, parse_dmarc_policy(record)}
        end

      {:error, :nxdomain} ->
        {:ok, %{error: "No valid DMARC record found"}}

      {:error, reason} ->
        {:ok, %{error: "DNS lookup failed: #{inspect(reason)}"}}
    end
  end

  @doc """
  Formats an IP tuple as a string.
  """
  @spec ip_to_string(ip()) :: String.t()
  def ip_to_string(ip), do: ip |> :inet.ntoa() |> to_string()

  @doc """
  Public resolvers used when the caller does not choose any.

  Cloudflare, Google, and Quad9's unfiltered service (`9.9.9.10`). This is
  the default for every function in this module and for `DomainTwistex.analyze/2`.
  """
  @spec public_nameservers() :: [String.t()]
  def public_nameservers, do: @public_nameservers

  @doc """
  Parses resolver specs (`"1.1.1.1"`, `"1.1.1.1:5353"`, IP tuples, or
  `{ip, port}`) into the `{ip_tuple, port}` form `:inet_res` expects.
  """
  @spec parse_nameservers([String.t() | tuple()] | nil) :: [{ip(), :inet.port_number()}] | nil
  def parse_nameservers(nil), do: nil
  def parse_nameservers([]), do: nil
  def parse_nameservers(list), do: Enum.map(list, &parse_nameserver/1)

  defp parse_nameserver({ip, port}) when is_tuple(ip) and is_integer(port), do: {ip, port}
  defp parse_nameserver(ip) when is_tuple(ip), do: {ip, 53}

  defp parse_nameserver(spec) when is_binary(spec) do
    case parse_ip(spec, 53) do
      {:ok, ns} ->
        ns

      {:error, _} ->
        with [_, host, port] <- Regex.run(~r/^\[?(.+?)\]?:(\d+)$/, spec),
             {:ok, ns} <- parse_ip(host, String.to_integer(port)) do
          ns
        else
          _ -> raise ArgumentError, "invalid nameserver: #{inspect(spec)}"
        end
    end
  end

  defp parse_ip(host, port) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> {:ok, {ip, port}}
      error -> error
    end
  end

  # =============================================================================
  # Private Functions
  # =============================================================================

  # Runs a query over UDP, falling back to TCP only on truncation and
  # retrying on timeout/SERVFAIL against the next resolver. EDNS0 is only
  # used for TXT (the only large responses we fetch); many home-router and
  # VPN resolvers mishandle it, and A/MX/NS answers fit in plain DNS.
  defp query(name, type, opts) do
    timeout = Keyword.get(opts, :dns_timeout, @default_timeout)
    retries = Keyword.get(opts, :retries, 1)
    do_query(String.to_charlist(name), type, opts, timeout, retries, 0)
  end

  @edns_rejections [:qfmterror, :formerr, :badvers, :notimp]

  defp do_query(name, type, opts, timeout, retries, attempt) do
    base = resolver_opts(name, opts, attempt)

    result =
      case udp_then_tcp(name, type, edns_opts(type) ++ base, base, timeout) do
        {:error, reason} when reason in @edns_rejections and type == :txt ->
          udp_then_tcp(name, type, base, base, timeout)

        other ->
          other
      end

    case result do
      {:error, reason} when reason in [:timeout, :servfail] and attempt < retries ->
        do_query(name, type, opts, timeout, retries, attempt + 1)

      other ->
        other
    end
  end

  defp udp_then_tcp(name, type, udp_opts, base, timeout) do
    case resolve(name, type, udp_opts, timeout) do
      {:ok, msg} ->
        if :inet_dns.header(:inet_dns.msg(msg, :header), :tc),
          do: resolve(name, type, [usevc: true] ++ base, timeout),
          else: {:ok, msg}

      error ->
        error
    end
  end

  defp edns_opts(:txt), do: [edns: 0, udp_payload_size: 4096]
  defp edns_opts(_type), do: []

  defp resolve(name, type, res_opts, timeout) do
    case :inet_res.resolve(name, :in, type, res_opts, timeout) do
      {:ok, msg} -> {:ok, msg}
      {:error, {reason, _msg}} when is_atom(reason) -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  catch
    :exit, _ -> {:error, :timeout}
  end

  # Rotates the resolver list per name (and per retry) to spread load.
  # A missing :nameservers key means the public pool; an explicit nil means
  # the system resolver.
  defp resolver_opts(name, opts, attempt) do
    case parse_nameservers(Keyword.get(opts, :nameservers, @public_nameservers)) do
      nil ->
        []

      nameservers ->
        offset = rem(:erlang.phash2(name) + attempt, length(nameservers))
        {head, tail} = Enum.split(nameservers, offset)
        [nameservers: tail ++ head]
    end
  end

  defp rr_data(answers, type) do
    for rr <- answers, :inet_dns.rr(rr, :type) == type, do: :inet_dns.rr(rr, :data)
  end

  # TXT data is arbitrary bytes; keep results valid UTF-8 for JSON output
  defp txt_to_string(data) do
    data
    |> List.flatten()
    |> :erlang.list_to_binary()
    |> String.replace_invalid()
    |> String.trim()
  end

  defp random_label do
    "dtx-" <> (:crypto.strong_rand_bytes(10) |> Base.encode16(case: :lower))
  end

  defp parse_dmarc_policy(record) do
    record
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reduce(%{}, fn part, acc ->
      case String.split(part, "=", parts: 2) do
        [key, value] -> Map.put(acc, String.trim(key), String.trim(value))
        _ -> acc
      end
    end)
  end
end
