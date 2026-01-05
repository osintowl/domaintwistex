defmodule DomainTwistex.Utils.Whois do
  @moduledoc """
  WHOIS and RDAP client for domain information lookup.

  This module implements RDAP-first lookup with WHOIS fallback,
  using IANA RDAP bootstrap discovery and comprehensive TLD mappings.

  ## WHOIS Server Data

  WHOIS server mappings are sourced from IANA via the iana-whois-conf project,
  which scrapes https://www.iana.org/domains/root/db/{tld}.html pages.

  To update the WHOIS server list, run:

      mix update_whois_servers

  """

  @iana_rdap_bootstrap_url "https://data.iana.org/rdap/dns.json"

  # Cache the IANA bootstrap registry in process dictionary for performance
  @rdap_cache_key :rdap_bootstrap_cache

  # Load WHOIS servers from IANA-sourced data at compile time
  @external_resource whois_servers_path = Path.join(:code.priv_dir(:domaintwistex), "whois_servers.json")

  @whois_servers (
    case File.read(whois_servers_path) do
      {:ok, json} ->
        Jason.decode!(json)

      {:error, _} ->
        # Fallback for when priv file doesn't exist (e.g., during initial compile)
        %{
          "com" => "whois.verisign-grs.com",
          "net" => "whois.verisign-grs.com",
          "org" => "whois.publicinterestregistry.org",
          "io" => "whois.nic.io"
        }
    end
  )

  @doc """
  Checks if a domain is registered.

  Returns {:ok, true} if registered, {:ok, false} if not, {:error, reason} on failure.
  """
  def is_registered?(domain) do
    case lookup(domain) do
      {:ok, %{status: status}} when is_list(status) ->
        # Check for "not found" type statuses
        not_found = Enum.any?(status, fn s ->
          s_lower = String.downcase(to_string(s))
          String.contains?(s_lower, "available") or
          String.contains?(s_lower, "no match") or
          String.contains?(s_lower, "not found")
        end)
        {:ok, not not_found}

      {:ok, _data} ->
        # Got data back, domain is registered
        {:ok, true}

      {:error, reason} when is_binary(reason) ->
        # Check if error indicates domain not found
        reason_lower = String.downcase(reason)
        if String.contains?(reason_lower, "not found") or
           String.contains?(reason_lower, "no match") or
           String.contains?(reason_lower, "available") do
          {:ok, false}
        else
          {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    _ -> {:error, :lookup_failed}
  end

  # Marker for fields not available in WHOIS fallback
  @whois_not_available "Not available in WHOIS"

  # Marker for fields redacted by RDAP provider (e.g., due to GDPR)
  @rdap_redacted "Redacted by provider"

  @doc """
  Performs a WHOIS/RDAP lookup for the given domain.

  This function tries RDAP first using IANA bootstrap registry,
  then falls back to traditional WHOIS if RDAP is not available.

  ## Parameters
    * domain - String representing the domain to lookup

  ## Returns
    {:ok, map} or {:error, reason} where map contains:
      * :domain - The domain that was looked up
      * :source - Either "rdap" or "whois"
      * :raw_data - Raw response text
      * :registrar - Domain registrar name (optional)
      * :creation_date - Domain creation date (optional)
      * :expiration_date - Domain expiration date (optional)
      * :updated_date - Last update date (optional)
      * :status - List of domain status codes (optional)
      * :nameservers - List of nameservers (optional)
      * :registrant - Registrant contact info map (optional)
      * :admin_contact - Admin contact info map (optional)
      * :tech_contact - Technical contact info map (optional)
      * :abuse_contact - Abuse contact info map (optional)
  """
  def lookup(domain) do
    case try_rdap_lookup(domain) do
      {:ok, data} -> {:ok, data}
      {:error, _} -> try_whois_lookup(domain)
    end
  end

  defp try_rdap_lookup(domain) do
    tld = extract_tld(domain)

    case get_rdap_server_for_tld(tld) do
      {:ok, rdap_base_url} ->
        url = "#{rdap_base_url}domain/#{domain}"

        case Req.get(url,
               receive_timeout: 5_000,
               connect_options: [transport_opts: [verify: :verify_none]],
               retry: :transient,
               retry_delay: fn attempt -> min(1000 * attempt, 5_000) end,
               max_retries: 2
             ) do
          {:ok, %Req.Response{status: 200, body: rdap_data}} ->
            {:ok, parse_rdap_response(domain, rdap_data, inspect(rdap_data))}
          {:ok, %Req.Response{status: 404}} ->
            {:error, "Domain not found in RDAP"}
          {:ok, %Req.Response{status: status}} ->
            {:error, "RDAP server returned status #{status}"}
          {:error, %Req.TransportError{reason: reason}} ->
            {:error, "RDAP request failed: #{inspect(reason)}"}
          {:error, reason} ->
            {:error, "RDAP request failed: #{inspect(reason)}"}
        end
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_rdap_server_for_tld(tld) do
    case fetch_iana_rdap_bootstrap() do
      {:ok, registry} ->
        case find_rdap_server_in_registry(tld, registry) do
          nil -> {:error, "No RDAP server found for TLD: #{tld}"}
          server -> {:ok, server}
        end
      {:error, _} ->
        {:error, "Failed to fetch IANA RDAP bootstrap registry"}
    end
  end

  defp fetch_iana_rdap_bootstrap() do
    # Check cache first
    case Process.get(@rdap_cache_key) do
      nil ->
        case Req.get(@iana_rdap_bootstrap_url, receive_timeout: 10_000, connect_options: [transport_opts: [verify: :verify_none]]) do
          {:ok, %Req.Response{status: 200, body: data}} ->
            Process.put(@rdap_cache_key, data)
            {:ok, data}
          {:ok, %Req.Response{status: status}} ->
            {:error, "IANA RDAP bootstrap returned status #{status}"}
          {:error, reason} ->
            {:error, "Failed to fetch IANA RDAP bootstrap: #{inspect(reason)}"}
        end
      cached_data ->
        {:ok, cached_data}
    end
  end

  defp find_rdap_server_in_registry(tld, registry) do
    services = Map.get(registry, "services", [])

    Enum.find_value(services, fn [tlds, servers] ->
      if tld in tlds do
        List.first(servers)
      end
    end)
  end

  defp try_whois_lookup(domain) do
    tld = extract_tld(domain)

    case Map.get(@whois_servers, tld) do
      nil -> {:error, "No WHOIS server for TLD: #{tld}"}
      whois_server ->
        case tcp_whois_query(whois_server, domain) do
          {:ok, raw_data} ->
            registered = not (String.contains?(String.downcase(raw_data), "no match") or
                             String.contains?(String.downcase(raw_data), "not found") or
                             String.contains?(String.downcase(raw_data), "available"))
            {:ok, %{
              domain: domain,
              source: "whois",
              raw_data: raw_data,
              registered: registered,
              registrar: parse_whois_field(raw_data, "Registrar"),
              creation_date: parse_whois_field(raw_data, "Creation Date"),
              expiration_date: parse_whois_field(raw_data, "Expir"),
              updated_date: parse_whois_field(raw_data, "Updated Date"),
              status: parse_whois_status(raw_data),
              nameservers: parse_whois_nameservers(raw_data),
              registrant: @whois_not_available,
              admin_contact: @whois_not_available,
              tech_contact: @whois_not_available,
              abuse_contact: @whois_not_available
            }}
          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp parse_whois_field(raw_data, field_prefix) do
    raw_data
    |> String.split("\n")
    |> Enum.find_value(fn line ->
      if String.contains?(String.downcase(line), String.downcase(field_prefix)) do
        case String.split(line, ":", parts: 2) do
          [_, value] -> String.trim(value)
          _ -> nil
        end
      end
    end)
  end

  defp parse_whois_status(raw_data) do
    statuses =
      raw_data
      |> String.split("\n")
      |> Enum.filter(fn line ->
        line_lower = String.downcase(line)
        String.contains?(line_lower, "status:") or String.contains?(line_lower, "domain status:")
      end)
      |> Enum.map(fn line ->
        case String.split(line, ":", parts: 2) do
          [_, value] ->
            value
            |> String.trim()
            |> String.split(" ")
            |> List.first()

          _ ->
            nil
        end
      end)
      |> Enum.filter(&(&1 != nil and &1 != ""))

    case statuses do
      [] -> nil
      list -> Enum.uniq(list)
    end
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
          [_, value] -> String.trim(value) |> String.downcase()
          _ -> nil
        end
      end)
      |> Enum.filter(&(&1 != nil and &1 != ""))

    case nameservers do
      [] -> nil
      list -> Enum.uniq(list)
    end
  end

  defp tcp_whois_query(server, domain) do
    case :gen_tcp.connect(
           String.to_charlist(server),
           43,
           [:binary, {:packet, 0}, {:active, false}],
           3_000
         ) do
      {:ok, socket} ->
        query = "#{domain}\r\n"
        :gen_tcp.send(socket, query)
        result = recv_all(socket, <<>>)
        :gen_tcp.close(socket)
        result
      {:error, reason} ->
        {:error, "Failed to connect to WHOIS server: #{inspect(reason)}"}
    end
  end

  defp recv_all(socket, acc) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> recv_all(socket, acc <> data)
      {:error, :closed} -> {:ok, acc}
      {:error, :timeout} when byte_size(acc) > 0 -> {:ok, acc}
      {:error, reason} -> {:error, "Failed to receive WHOIS data: #{inspect(reason)}"}
    end
  end

  defp parse_rdap_response(domain, rdap_data, raw_data) do
    entities = Map.get(rdap_data, "entities", [])

    %{
      domain: domain,
      source: "rdap",
      raw_data: raw_data,
      registered: true,
      registrar: extract_rdap_registrar(rdap_data),
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

  defp extract_rdap_registrar(rdap_data) do
    entities = Map.get(rdap_data, "entities", [])

    Enum.find_value(entities, fn entity ->
      roles = Map.get(entity, "roles", [])
      if "registrar" in roles do
        vcard_array = Map.get(entity, "vcardArray", [])
        extract_vcard_name(vcard_array)
      end
    end)
  end

  defp extract_vcard_name(vcard_array) when is_list(vcard_array) and length(vcard_array) >= 2 do
    properties = Enum.at(vcard_array, 1)

    if is_list(properties) do
      Enum.find_value(properties, fn prop ->
        case prop do
          [name, _, _, value] when name in ["fn", "org"] and is_binary(value) -> value
          _ -> nil
        end
      end)
    end
  end
  defp extract_vcard_name(_), do: nil

  # Extract full contact info from an entity by role
  # Searches both top-level entities and nested entities (e.g., abuse contact nested in registrar)
  defp extract_entity_by_role(entities, role) do
    # First try to find at top level
    entity = Enum.find(entities, fn entity ->
      roles = Map.get(entity, "roles", [])
      role in roles
    end)

    case entity do
      nil ->
        # Search nested entities (common for abuse contacts nested in registrar)
        case find_nested_entity(entities, role) do
          nil -> @rdap_redacted
          result -> result
        end

      entity ->
        extract_vcard_contact(entity)
    end
  end

  # Search for entities nested within other entities
  defp find_nested_entity(entities, role) do
    Enum.find_value(entities, fn entity ->
      nested = Map.get(entity, "entities", [])

      nested_entity = Enum.find(nested, fn nested_entity ->
        roles = Map.get(nested_entity, "roles", [])
        role in roles
      end)

      case nested_entity do
        nil -> nil
        found -> extract_vcard_contact(found)
      end
    end)
  end

  # Extract comprehensive contact info from vCard
  defp extract_vcard_contact(entity) do
    vcard_array = Map.get(entity, "vcardArray", [])

    case vcard_array do
      ["vcard", properties] when is_list(properties) ->
        contact = %{
          name: extract_vcard_property(properties, "fn") |> normalize_empty(),
          organization: extract_vcard_property(properties, "org") |> normalize_empty(),
          email: extract_vcard_property(properties, "email") |> normalize_empty(),
          phone: extract_vcard_phone(properties) |> normalize_empty(),
          fax: extract_vcard_fax(properties) |> normalize_empty(),
          address: extract_vcard_address(properties),
          country: extract_vcard_country(properties)
        }

        # Consider contact redacted if primary identifying fields are missing
        # (name, organization, and address all nil means the contact is essentially redacted)
        primary_fields = [contact.name, contact.organization, contact.address]
        has_primary_data = Enum.any?(primary_fields, &(&1 != nil))

        if has_primary_data do
          contact
        else
          @rdap_redacted
        end

      _ ->
        @rdap_redacted
    end
  end

  # Convert empty strings to nil
  defp normalize_empty(""), do: nil
  defp normalize_empty(value), do: value

  # Extract a simple property value from vCard
  defp extract_vcard_property(properties, prop_name) do
    Enum.find_value(properties, fn prop ->
      case prop do
        [^prop_name, _params, _type, value] when is_binary(value) ->
          String.trim(value)

        [^prop_name, _params, _type, values] when is_list(values) ->
          # For org, it might be a list
          values
          |> Enum.filter(&is_binary/1)
          |> Enum.join(", ")
          |> case do
            "" -> nil
            str -> String.trim(str)
          end

        _ ->
          nil
      end
    end)
  end

  # Extract phone number, handling tel: URI format
  defp extract_vcard_phone(properties) do
    Enum.find_value(properties, fn prop ->
      case prop do
        ["tel", params, _type, value] when is_binary(value) ->
          # Skip fax numbers
          if is_fax_type?(params) do
            nil
          else
            clean_phone_value(value)
          end

        _ ->
          nil
      end
    end)
  end

  # Clean phone value, removing tel: prefix if present
  defp clean_phone_value(value) do
    value
    |> String.trim()
    |> String.replace_prefix("tel:", "")
  end

  # Extract fax specifically (tel with type=fax)
  defp extract_vcard_fax(properties) do
    Enum.find_value(properties, fn prop ->
      case prop do
        ["tel", params, _type, value] when is_binary(value) ->
          if is_fax_type?(params), do: clean_phone_value(value), else: nil

        _ ->
          nil
      end
    end)
  end

  defp is_fax_type?(params) when is_map(params) do
    case Map.get(params, "type") do
      types when is_list(types) -> "fax" in Enum.map(types, &String.downcase/1)
      type when is_binary(type) -> String.downcase(type) == "fax"
      _ -> false
    end
  end
  defp is_fax_type?(_), do: false

  # Extract full address from vCard adr property
  defp extract_vcard_address(properties) do
    Enum.find_value(properties, fn prop ->
      case prop do
        ["adr", _params, _type, components] when is_list(components) ->
          # vCard adr: [PO Box, Extended, Street, City, Region, Postal, Country]
          address_parts =
            components
            |> Enum.filter(&is_binary/1)
            |> Enum.map(&String.trim/1)
            |> Enum.filter(&(&1 != ""))

          case address_parts do
            [] -> nil
            parts -> Enum.join(parts, ", ")
          end

        _ ->
          nil
      end
    end)
  end

  # Extract country from vCard (last element of adr or from country param)
  defp extract_vcard_country(properties) do
    Enum.find_value(properties, fn prop ->
      case prop do
        ["adr", _params, _type, components] when is_list(components) ->
          # Country is typically the 7th element (index 6) in adr
          case Enum.at(components, 6) do
            country when is_binary(country) and country != "" -> String.trim(country)
            _ -> nil
          end

        _ ->
          nil
      end
    end)
  end

  defp extract_rdap_event_date(rdap_data, event_type) do
    events = Map.get(rdap_data, "events", [])

    Enum.find_value(events, fn event ->
      action = Map.get(event, "eventAction", "")
      if String.contains?(String.downcase(action), event_type) do
        Map.get(event, "eventDate")
      end
    end)
  end

  defp extract_rdap_status(rdap_data) do
    case Map.get(rdap_data, "status", []) do
      [] -> nil
      status -> status
    end
  end

  defp extract_rdap_nameservers(rdap_data) do
    nameservers = Map.get(rdap_data, "nameservers", [])

    ns_list = Enum.map(nameservers, fn ns ->
      Map.get(ns, "ldhName", "")
    end)
    |> Enum.filter(&(&1 != ""))

    case ns_list do
      [] -> nil
      list -> list
    end
  end

  defp extract_tld(domain) do
    domain
    |> String.split(".")
    |> List.last()
    |> String.downcase()
  end
end
