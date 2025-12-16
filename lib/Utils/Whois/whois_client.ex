defmodule DomainTwistex.Utils.Whois do
  @moduledoc """
  WHOIS and RDAP client for domain information lookup.

  This module implements RDAP-first lookup with WHOIS fallback,
  using IANA RDAP bootstrap discovery and comprehensive TLD mappings.
  """

  @iana_rdap_bootstrap_url "https://data.iana.org/rdap/dns.json"

  # Cache the IANA bootstrap registry in process dictionary for performance
  @rdap_cache_key :rdap_bootstrap_cache

  # WHOIS server mappings for fallback
  @whois_servers %{
    # Generic TLDs
    "com" => "whois.verisign-grs.com",
    "net" => "whois.verisign-grs.com",
    "org" => "whois.pir.org",
    "info" => "whois.afilias.net",
    "biz" => "whois.neulevel.biz",
    "name" => "whois.nic.name",
    "pro" => "whois.afilias.net",
    "aero" => "whois.afilias.net",
    "asia" => "whois.nic.asia",
    "cat" => "whois.nic.cat",
    "coop" => "whois.nic.coop",
    "edu" => "whois.educause.edu",
    "gov" => "whois.dotgov.gov",
    "int" => "whois.iana.org",
    "jobs" => "whois.nic.jobs",
    "mil" => "whois.nic.mil",
    "mobi" => "whois.afilias.net",
    "museum" => "whois.nic.museum",
    "post" => "whois.dotpostregistry.net",
    "tel" => "whois.nic.tel",
    "travel" => "whois.nic.travel",
    "xxx" => "whois.afilias.net",

    # Country Code TLDs (popular ones)
    "ac" => "whois.nic.ac",
    "ae" => "whois.aeda.net.ae",
    "af" => "whois.nic.af",
    "ag" => "whois.nic.ag",
    "ai" => "whois.nic.ai",
    "am" => "whois.nic.am",
    "ar" => "whois.nic.ar",
    "as" => "whois.nic.as",
    "at" => "whois.nic.at",
    "au" => "whois.aunic.net",
    "be" => "whois.dns.be",
    "bg" => "whois.nic.bg",
    "br" => "whois.registro.br",
    "by" => "whois.nic.by",
    "bz" => "whois.nic.bz",
    "ca" => "whois.cira.ca",
    "cc" => "whois.nic.cc",
    "ch" => "whois.nic.ch",
    "cl" => "whois.nic.cl",
    "cn" => "whois.cnnic.net.cn",
    "co" => "whois.nic.co",
    "cz" => "whois.nic.cz",
    "de" => "whois.denic.de",
    "dk" => "whois.dk-hostmaster.dk",
    "ee" => "whois.eesti.ee",
    "es" => "whois.nic.es",
    "eu" => "whois.eu",
    "fi" => "whois.ficora.fi",
    "fm" => "whois.nic.fm",
    "fr" => "whois.nic.fr",
    "gg" => "whois.nic.gg",
    "gr" => "whois.nic.gr",
    "hk" => "whois.hkirc.hk",
    "hr" => "whois.nic.hr",
    "hu" => "whois.nic.hu",
    "id" => "whois.nic.id",
    "ie" => "whois.nic.ie",
    "il" => "whois.nic.il",
    "im" => "whois.nic.im",
    "in" => "whois.nic.in",
    "io" => "whois.nic.io",
    "ir" => "whois.nic.ir",
    "is" => "whois.isnic.is",
    "it" => "whois.nic.it",
    "je" => "whois.nic.je",
    "jp" => "whois.jprs.jp",
    "ke" => "whois.nic.ke",
    "kr" => "whois.nic.or.kr",
    "kz" => "whois.nic.kz",
    "la" => "whois.nic.la",
    "li" => "whois.nic.li",
    "lt" => "whois.nic.lt",
    "lu" => "whois.nic.lu",
    "lv" => "whois.nic.lv",
    "ly" => "whois.nic.ly",
    "ma" => "whois.nic.ma",
    "md" => "whois.nic.md",
    "me" => "whois.nic.me",
    "mg" => "whois.nic.mg",
    "mk" => "whois.nic.mk",
    "mn" => "whois.nic.mn",
    "ms" => "whois.nic.ms",
    "mu" => "whois.nic.mu",
    "mx" => "whois.mx",
    "my" => "whois.nic.my",
    "na" => "whois.nic.na",
    "nc" => "whois.nic.nc",
    "nl" => "whois.domain-registry.nl",
    "no" => "whois.norid.no",
    "nu" => "whois.nic.nu",
    "nz" => "whois.srs.net.nz",
    "pe" => "whois.nic.pe",
    "pl" => "whois.dns.pl",
    "pm" => "whois.nic.pm",
    "pr" => "whois.nic.pr",
    "pt" => "whois.nic.pt",
    "pw" => "whois.nic.pw",
    "qa" => "whois.nic.qa",
    "re" => "whois.nic.re",
    "ro" => "whois.nic.ro",
    "rs" => "whois.nic.rs",
    "ru" => "whois.ripn.net",
    "sa" => "whois.nic.sa",
    "sc" => "whois.nic.sc",
    "se" => "whois.iis.se",
    "sg" => "whois.nic.sg",
    "sh" => "whois.nic.sh",
    "si" => "whois.nic.si",
    "sk" => "whois.nic.sk",
    "sm" => "whois.nic.sm",
    "so" => "whois.nic.so",
    "st" => "whois.nic.st",
    "su" => "whois.nic.su",
    "tc" => "whois.nic.tc",
    "tf" => "whois.nic.tf",
    "th" => "whois.nic.th",
    "tk" => "whois.nic.tk",
    "tl" => "whois.nic.tl",
    "tm" => "whois.nic.tm",
    "tn" => "whois.nic.tn",
    "to" => "whois.nic.to",
    "tr" => "whois.nic.tr",
    "tv" => "whois.nic.tv",
    "tw" => "whois.nic.tw",
    "ua" => "whois.nic.ua",
    "ug" => "whois.nic.ug",
    "uk" => "whois.nic.uk",
    "us" => "whois.nic.us",
    "uy" => "whois.nic.uy",
    "uz" => "whois.nic.uz",
    "vc" => "whois.nic.vc",
    "ve" => "whois.nic.ve",
    "vg" => "whois.nic.vg",
    "ws" => "whois.nic.ws",
    "za" => "whois.registry.net.za"
  }

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
              status: nil,
              nameservers: nil
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
      nameservers: extract_rdap_nameservers(rdap_data)
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
