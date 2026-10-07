defmodule DomainTwistex.Whois do
  @moduledoc """
  WHOIS and RDAP client for domain information lookup.

  Implements RDAP-first lookup with WHOIS fallback, using IANA RDAP bootstrap
  discovery and IANA-sourced WHOIS server mappings.

  ## Caching

  The IANA RDAP bootstrap registry is indexed into a `tld => base_url` map and
  cached with `:persistent_term` for efficient reads across all processes.
  Fetches are serialized, and failures are cached briefly.

  ## WHOIS Server Data

  WHOIS server mappings are sourced from IANA. To update:

      mix update_whois_servers

  """

  @iana_rdap_bootstrap_url "https://data.iana.org/rdap/dns.json"
  @rdap_cache_key :domaintwistex_rdap_bootstrap

  # Load WHOIS servers at compile time (regenerate with `mix update_whois_servers`)
  @external_resource whois_servers_path =
                       Path.join(:code.priv_dir(:domaintwistex), "whois_servers.json")

  @whois_servers whois_servers_path |> File.read!() |> Jason.decode!()

  @whois_not_available "Not available in WHOIS"
  @rdap_redacted "Redacted by provider"

  @type lookup_result :: {:ok, map()} | {:error, String.t() | atom()}

  @doc """
  Checks if a domain is registered.

  ## Returns

    * `{:ok, true}` - Domain is registered
    * `{:ok, false}` - Domain is available
    * `{:error, reason}` - Lookup failed

  """
  @spec is_registered?(String.t()) :: {:ok, boolean()} | {:error, any()}
  def is_registered?(domain) do
    case lookup(domain) do
      {:ok, %{registered: registered}} -> {:ok, registered}
      {:error, "Domain not found in RDAP"} -> {:ok, false}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Performs a WHOIS/RDAP lookup for the given domain.

  Tries RDAP first using IANA bootstrap registry, then falls back to
  traditional WHOIS if RDAP is not available. An RDAP 404 is treated as
  authoritative (not registered) and does not fall back.

  ## Options

    * `:raw` - Include the raw response in `:raw_data` (default: false)

  ## Returns

    `{:ok, map}` or `{:error, reason}` where map contains:
      * `:domain` - The domain looked up
      * `:source` - "rdap" or "whois"
      * `:registrar` - Domain registrar name
      * `:creation_date` - Domain creation date
      * `:expiration_date` - Domain expiration date
      * `:status` - List of domain status codes
      * `:nameservers` - List of nameservers

  """
  @spec lookup(String.t(), keyword()) :: lookup_result()
  def lookup(domain, opts \\ []) do
    domain = DomainTwistex.IDNA.to_ascii(domain)

    result =
      case try_rdap_lookup(domain) do
        {:ok, data} -> {:ok, data}
        # RDAP 404 is authoritative; WHOIS would only add latency
        {:error, :not_found} -> {:error, "Domain not found in RDAP"}
        {:error, _} -> try_whois_lookup(domain)
      end

    case result do
      {:ok, data} -> {:ok, if(Keyword.get(opts, :raw, false), do: data, else: Map.delete(data, :raw_data))}
      error -> error
    end
  end

  @doc """
  Fetches and caches the IANA RDAP bootstrap registry ahead of a scan.

  Safe to call concurrently: only one process fetches, the rest wait for
  the cached result. Failures are cached for five minutes so a
  scan doesn't hammer IANA when it is unreachable.
  """
  @spec prefetch_bootstrap() :: :ok | {:error, String.t()}
  def prefetch_bootstrap do
    case rdap_servers() do
      {:ok, _} -> :ok
      {:error, _} = error -> error
    end
  end

  @doc """
  Clears the RDAP bootstrap cache.

  Useful for testing or forcing a refresh.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    :persistent_term.erase(@rdap_cache_key)
    :ok
  end

  # =============================================================================
  # RDAP Lookup
  # =============================================================================

  @bootstrap_failure_ttl_ms 300_000

  defp try_rdap_lookup(domain) do
    tld = extract_tld(domain)

    with {:ok, servers} <- rdap_servers(),
         {:ok, base_url} <- Map.fetch(servers, tld) |> or_error("No RDAP server found for TLD: #{tld}") do
      case Req.get(base_url <> "domain/" <> domain,
             receive_timeout: 5_000,
             retry: :transient,
             retry_delay: fn attempt -> min(1000 * attempt, 5_000) end,
             max_retries: 2
           ) do
        {:ok, %Req.Response{status: 200, body: %{} = rdap_data}} ->
          {:ok, parse_rdap_response(domain, rdap_data)}

        {:ok, %Req.Response{status: 200}} ->
          {:error, "RDAP server returned a non-JSON body"}

        {:ok, %Req.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Req.Response{status: status}} ->
          {:error, "RDAP server returned status #{status}"}

        {:error, reason} ->
          {:error, "RDAP request failed: #{inspect(reason)}"}
      end
    end
  end

  defp or_error({:ok, _} = ok, _message), do: ok
  defp or_error(:error, message), do: {:error, message}

  # %{tld => base_url} cached in persistent_term (shared across all processes)
  defp rdap_servers do
    case cached_bootstrap() do
      {:ok, servers} ->
        {:ok, servers}

      :miss ->
        # Serialize the fetch so a cold cache doesn't trigger a stampede of
        # IANA requests (and a global GC per persistent_term.put)
        :global.trans({@rdap_cache_key, self()}, fn ->
          case cached_bootstrap() do
            :miss -> fetch_and_cache_bootstrap()
            cached -> cached
          end
        end, [node()])
    end
  end

  defp cached_bootstrap do
    case :persistent_term.get(@rdap_cache_key, nil) do
      nil ->
        :miss

      {:error, reason, expires_at} ->
        if System.monotonic_time(:millisecond) < expires_at, do: {:error, reason}, else: :miss

      servers ->
        {:ok, servers}
    end
  end

  defp fetch_and_cache_bootstrap do
    result =
      case Req.get(@iana_rdap_bootstrap_url, receive_timeout: 10_000, retry: :transient, max_retries: 2) do
        {:ok, %Req.Response{status: 200, body: %{"services" => services}}} ->
          {:ok, index_services(services)}

        {:ok, %Req.Response{status: status}} ->
          {:error, "IANA RDAP bootstrap returned status #{status}"}

        {:error, reason} ->
          {:error, "Failed to fetch IANA RDAP bootstrap: #{inspect(reason)}"}
      end

    case result do
      {:ok, servers} ->
        :persistent_term.put(@rdap_cache_key, servers)

      {:error, reason} ->
        expires_at = System.monotonic_time(:millisecond) + @bootstrap_failure_ttl_ms
        :persistent_term.put(@rdap_cache_key, {:error, reason, expires_at})
    end

    result
  end

  defp index_services(services) do
    for [tlds, [url | _]] <- services,
        tld <- tlds,
        into: %{},
        do: {String.downcase(tld), if(String.ends_with?(url, "/"), do: url, else: url <> "/")}
  end

  # =============================================================================
  # WHOIS Lookup
  # =============================================================================

  defp try_whois_lookup(domain) do
    tld = extract_tld(domain)

    case Map.get(@whois_servers, tld) do
      nil ->
        {:error, "No WHOIS server for TLD: #{tld}"}

      whois_server ->
        case tcp_whois_query(whois_server, domain) do
          {:ok, raw_data} ->
            {:ok, parse_whois_response(domain, raw_data)}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp tcp_whois_query(server, domain) do
    case :gen_tcp.connect(String.to_charlist(server), 43, [:binary, packet: 0, active: false], 3_000) do
      {:ok, socket} ->
        :gen_tcp.send(socket, "#{domain}\r\n")
        result = recv_all(socket, <<>>)
        :gen_tcp.close(socket)
        result

      {:error, reason} ->
        {:error, "Failed to connect to WHOIS server: #{inspect(reason)}"}
    end
  end

  @max_whois_bytes 256 * 1024

  defp recv_all(_socket, acc) when byte_size(acc) >= @max_whois_bytes, do: {:ok, acc}

  defp recv_all(socket, acc) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> recv_all(socket, acc <> data)
      {:error, :closed} -> {:ok, acc}
      {:error, :timeout} when byte_size(acc) > 0 -> {:ok, acc}
      {:error, reason} -> {:error, "Failed to receive WHOIS data: #{inspect(reason)}"}
    end
  end

  # Line-anchored "not registered" markers used by common registries. Plain
  # substring checks for "available" match legal boilerplate on registered
  # domains, so these must match the start of a line. Kept in a function
  # because compiled regexes can't be stored in module attributes on OTP 28+.
  defp not_registered_patterns do
    [
      ~r/^\s*no match( for)?\b/im,
      ~r/^\s*not found\b/im,
      ~r/^\s*no (data|entries) found\b/im,
      ~r/^\s*domain not found\b/im,
      ~r/^\s*the queried object does not exist/im,
      ~r/^\s*status:\s*(free|available)\b/im,
      ~r/^%*\s*no such domain/im,
      ~r/is available for registration/im
    ]
  end

  defp parse_whois_response(domain, raw_data) do
    registered = not Enum.any?(not_registered_patterns(), &Regex.match?(&1, raw_data))

    %{
      domain: domain,
      source: "whois",
      raw_data: raw_data,
      registered: registered,
      registrar: parse_whois_field(raw_data, ["Registrar", "Sponsoring Registrar", "registrar name"]),
      creation_date:
        parse_whois_field(raw_data, ["Creation Date", "Created On", "Created", "Registered on", "Registration Time"]),
      expiration_date:
        parse_whois_field(raw_data, [
          "Registry Expiry Date",
          "Registrar Registration Expiration Date",
          "Expiration Date",
          "Expiry Date",
          "Expires On",
          "Expires",
          "paid-till"
        ]),
      updated_date: parse_whois_field(raw_data, ["Updated Date", "Last Updated On", "Last Modified", "Changed"]),
      status: parse_whois_status(raw_data),
      nameservers: parse_whois_nameservers(raw_data),
      registrant: @whois_not_available,
      admin_contact: @whois_not_available,
      tech_contact: @whois_not_available,
      abuse_contact: @whois_not_available
    }
  end

  # Matches exact "Key:" at the start of a line (so "Registrar" doesn't pick
  # up "Registrar URL:"), trying keys in priority order
  defp parse_whois_field(raw_data, keys) do
    lines = String.split(raw_data, ~r/\r?\n/)

    Enum.find_value(keys, fn key ->
      key_lower = String.downcase(key)

      Enum.find_value(lines, fn line ->
        with [k, v] <- String.split(line, ":", parts: 2),
             true <- String.downcase(String.trim(k)) == key_lower,
             value when value != "" <- String.trim(v) do
          value
        else
          _ -> nil
        end
      end)
    end)
  end

  defp parse_whois_status(raw_data) do
    statuses =
      raw_data
      |> String.split("\n")
      |> Enum.filter(fn line ->
        line_lower = String.downcase(line)
        String.contains?(line_lower, "status:")
      end)
      |> Enum.map(fn line ->
        case String.split(line, ":", parts: 2) do
          [_, value] -> value |> String.trim() |> String.split(" ") |> List.first()
          _ -> nil
        end
      end)
      |> Enum.filter(&(&1 != nil and &1 != ""))
      |> Enum.uniq()

    if statuses == [], do: nil, else: statuses
  end

  defp parse_whois_nameservers(raw_data) do
    nameservers =
      raw_data
      |> String.split("\n")
      |> Enum.filter(fn line ->
        line_lower = String.downcase(line)
        String.contains?(line_lower, "name server:") or String.contains?(line_lower, "nserver:")
      end)
      |> Enum.map(fn line ->
        case String.split(line, ":", parts: 2) do
          [_, value] -> value |> String.trim() |> String.downcase()
          _ -> nil
        end
      end)
      |> Enum.filter(&(&1 != nil and &1 != ""))
      |> Enum.uniq()

    if nameservers == [], do: nil, else: nameservers
  end

  # =============================================================================
  # RDAP Response Parsing
  # =============================================================================

  defp parse_rdap_response(domain, rdap_data) do
    entities = Map.get(rdap_data, "entities", [])

    %{
      domain: domain,
      source: "rdap",
      raw_data: inspect(rdap_data),
      registered: true,
      registrar: extract_rdap_registrar(entities),
      creation_date: extract_rdap_event_date(rdap_data, "registration"),
      expiration_date: extract_rdap_event_date(rdap_data, "expiration"),
      updated_date: extract_rdap_event_date(rdap_data, "last changed"),
      status: extract_rdap_status(rdap_data),
      nameservers: extract_rdap_nameservers(rdap_data),
      registrant: extract_entity_by_role(entities, "registrant"),
      admin_contact: extract_entity_by_role(entities, "administrative"),
      tech_contact: extract_entity_by_role(entities, "technical"),
      abuse_contact: extract_entity_by_role(entities, "abuse")
    }
  end

  defp extract_rdap_registrar(entities) do
    Enum.find_value(entities, fn entity ->
      if "registrar" in Map.get(entity, "roles", []) do
        extract_vcard_name(Map.get(entity, "vcardArray", []))
      end
    end)
  end

  defp extract_vcard_name(["vcard", properties]) when is_list(properties) do
    Enum.find_value(properties, fn
      [name, _, _, value] when name in ["fn", "org"] and is_binary(value) -> value
      _ -> nil
    end)
  end

  defp extract_vcard_name(_), do: nil

  defp extract_entity_by_role(entities, role) do
    entity = Enum.find(entities, fn e -> role in Map.get(e, "roles", []) end)

    case entity do
      nil ->
        # Search nested entities
        find_nested_entity(entities, role)

      entity ->
        extract_vcard_contact(entity)
    end
  end

  defp find_nested_entity(entities, role) do
    Enum.find_value(entities, fn entity ->
      nested = Map.get(entity, "entities", [])
      nested_entity = Enum.find(nested, fn e -> role in Map.get(e, "roles", []) end)

      case nested_entity do
        nil -> nil
        found -> extract_vcard_contact(found)
      end
    end) || @rdap_redacted
  end

  defp extract_vcard_contact(entity) do
    case Map.get(entity, "vcardArray", []) do
      ["vcard", properties] when is_list(properties) ->
        contact = %{
          name: extract_vcard_property(properties, "fn"),
          organization: extract_vcard_property(properties, "org"),
          email: extract_vcard_property(properties, "email"),
          phone: extract_vcard_phone(properties),
          address: extract_vcard_address(properties)
        }

        has_data = Enum.any?(Map.values(contact), &(&1 != nil))
        if has_data, do: contact, else: @rdap_redacted

      _ ->
        @rdap_redacted
    end
  end

  defp extract_vcard_property(properties, prop_name) do
    Enum.find_value(properties, fn
      [^prop_name, _, _, value] when is_binary(value) ->
        String.trim(value)

      [^prop_name, _, _, values] when is_list(values) ->
        values |> Enum.filter(&is_binary/1) |> Enum.join(", ") |> String.trim() |> normalize_empty()

      _ ->
        nil
    end)
  end

  defp extract_vcard_phone(properties) do
    Enum.find_value(properties, fn
      ["tel", params, _, value] when is_binary(value) ->
        if not is_fax?(params), do: String.replace(value, "tel:", "") |> String.trim()

      _ ->
        nil
    end)
  end

  defp is_fax?(params) when is_map(params) do
    case Map.get(params, "type") do
      types when is_list(types) -> "fax" in Enum.map(types, &String.downcase/1)
      type when is_binary(type) -> String.downcase(type) == "fax"
      _ -> false
    end
  end

  defp is_fax?(_), do: false

  defp extract_vcard_address(properties) do
    Enum.find_value(properties, fn
      ["adr", _, _, components] when is_list(components) ->
        components
        |> Enum.filter(&is_binary/1)
        |> Enum.map(&String.trim/1)
        |> Enum.filter(&(&1 != ""))
        |> case do
          [] -> nil
          parts -> Enum.join(parts, ", ")
        end

      _ ->
        nil
    end)
  end

  defp extract_rdap_event_date(rdap_data, event_type) do
    events = Map.get(rdap_data, "events", [])

    Enum.find_value(events, fn event ->
      action = Map.get(event, "eventAction", "") |> String.downcase()
      if String.contains?(action, event_type), do: Map.get(event, "eventDate")
    end)
  end

  defp extract_rdap_status(rdap_data) do
    case Map.get(rdap_data, "status", []) do
      [] -> nil
      status -> status
    end
  end

  defp extract_rdap_nameservers(rdap_data) do
    ns_list =
      rdap_data
      |> Map.get("nameservers", [])
      |> Enum.map(&Map.get(&1, "ldhName", ""))
      |> Enum.filter(&(&1 != ""))

    if ns_list == [], do: nil, else: ns_list
  end

  defp extract_tld(domain) do
    domain |> String.split(".") |> List.last() |> String.downcase()
  end

  defp normalize_empty(""), do: nil
  defp normalize_empty(value), do: value
end
