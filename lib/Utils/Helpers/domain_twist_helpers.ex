defmodule DomainTwistex.Utils do
  version = Mix.Project.config()[:version]
  # use Rustler, otp_app: :domaintwistex, crate: "domaintwistex"
  use RustlerPrecompiled,
    otp_app: :domaintwistex,
    crate: "domaintwistex", 
    version: version,
    base_url: "https://github.com/osintowl/domaintwistex/releases/download/v#{version}",
    targets: ~w(
      aarch64-apple-darwin
      aarch64-unknown-linux-gnu
      x86_64-apple-darwin
      x86_64-pc-windows-msvc
      x86_64-pc-windows-gnu
      x86_64-unknown-linux-gnu
    ),
    force_build: System.get_env("DOMAINTWISTEX_BUILD") in ["1", "true"] 
  alias DomainTwistex.DNS
  alias DomainTwistex.SPF
  alias DomainTwistex.Utils.Whois
  alias DomainTwistex.Utils.ContentSimilarity

  @moduledoc """
  DomainTwistEx provides domain permutation generation and validation utilities.
  Combines Rust NIFs for permutation generation with domain validation and server checking capabilities.

  ## Prerequisites
  - Rust and Cargo must be installed on your system
    Install from https://rustup.rs/

  If you see a `:enoent` error during compilation, ensure Rust/Cargo is installed
  and available in your PATH.
  """

  @doc group: "1. Native Implemented Functions (RUST)"
  @doc """
  Generates domain permutations using the Twistrs Rust library.

  This function is implemented as a Native Implemented Function (NIF) that interfaces 
  with the Twistrs Rust library for efficient domain permutation generation.

  ## Attribution
  This NIF wraps functionality from the Twistrs library:
  https://github.com/haveibeensquatted/twistrs

  ## Parameters
    * domain - String representing the domain to generate permutations for

  ## Returns
    List of generated domain permutation strings

  ## Examples
      ```
      iex(1)> DomainTwistex.Utils.generate_permutations("google.com")
      [
        %{kind: "Keyword", fqdn: "servicegoogle.com", tld: "com"},
        %{kind: "Homoglyph", fqdn: "ğöögle.com", tld: "com"},
        # ...
      ]
      ```
  """
  def generate_permutations(_domain), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Validates and resolves domain information while checking for TLD-related issues.

  ## Parameters
    * domain - String representing the domain to check
    * tld - String representing the top-level domain to validate against

  ## Returns
    * `{:ok, [string]}` - List of valid IP addresses
    * `{:error, reason}` - Error message when validation fails
  """
  # IPs to filter out (localhost, private, bogus)
  @bogus_ips [
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "::1",
    "localhost"
  ]

  # Private IP ranges (filter these out)
  @private_prefixes [
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31."
  ]

  def validate_domain_resolution(domain, tld) do
    case DNS.resolve_ips(domain) do
      {:ok, %{ips: ips, cname: cname}} ->
        # Classify IPs safely
        {public_ips, internal_ips} = try do
          Enum.split_with(ips, fn ip -> not bogus_ip?(ip) end)
        rescue
          _ -> {ips, []}
        catch
          _, _ -> {ips, []}
        end

        ip_flags = try do
          classify_ips(ips)
        rescue
          _ -> []
        catch
          _, _ -> []
        end

        cond do
          # CNAME matches TLD (registry wildcard)
          cname && cname == tld ->
            {:error, "tld matches false positive"}

          # Has at least some IPs (public or internal)
          ips != [] ->
            {:ok, %{ips: ips, public_ips: public_ips, internal_ips: internal_ips, flags: ip_flags}}

          true ->
            {:error, :no_records}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp bogus_ip?(ip) do
    ip in @bogus_ips or Enum.any?(@private_prefixes, &String.starts_with?(ip, &1))
  end

  defp classify_ips(ips) do
    flags = []

    flags = if Enum.any?(ips, &(&1 == "127.0.0.1")), do: [:localhost | flags], else: flags
    flags = if Enum.any?(ips, &(&1 == "0.0.0.0")), do: [:null_route | flags], else: flags
    flags = if Enum.any?(ips, &String.starts_with?(&1, "10.")), do: [:private_10 | flags], else: flags
    flags = if Enum.any?(ips, &String.starts_with?(&1, "192.168.")), do: [:private_192 | flags], else: flags
    flags = if Enum.any?(ips, fn ip -> Enum.any?(["172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."], &String.starts_with?(ip, &1)) end), do: [:private_172 | flags], else: flags

    flags
  end

  @doc """
  Performs comprehensive domain validation checks including DNS and server availability.

  ## Parameters
    * permutation - Map containing at least :fqdn and :tld keys

  ## Returns
    * `{:ok, map}` - Successfully checked domain with all information
    * `{:error, binary}` - Error message when checks fail
    * `{:error, :not_resolvable}` - When domain cannot be resolved

  ## Example
      ```
      iex> permutation = %{fqdn: "example.com", tld: "com"}
      iex> DomainTwistex.Utils.check_domain(permutation)
      {:ok, %{
        resolvable: true,
        ip_addresses: ["93.184.216.34"],
        mx_records: [%{priority: 10, server: "mail.example.com"}],
        txt_records: ["v=spf1 -all"],
        server_response: %{status_code: "200", server: "ECS"},
        nameservers: ["ns1.example.com", "ns2.example.com"]
      }}
      ```
  """
  def check_domain(permutation, domain, opts \\ []) do
    include_whois = Keyword.get(opts, :whois, false)
    original_content = Keyword.get(opts, :original_content, nil)

    # A-record-first approach (like dnstwist) - fast, finds active domains
    case validate_domain_resolution(permutation.fqdn, permutation.tld) do
      {:ok, %{ips: ips, public_ips: public_ips, internal_ips: internal_ips, flags: ip_flags}} ->
        # Domain resolves - collect additional DNS data (best-effort)
        mx_records = safe_dns_query(fn -> DNS.get_mx_records(permutation.fqdn) end, [])
        txt_records = safe_dns_query(fn -> DNS.get_txt_records(permutation.fqdn) end, [])
        spf_records = SPF.parse_txt_records({:ok, txt_records})
        dmarc = safe_dns_query(fn -> DNS.check_dmarc(permutation.fqdn) end, %{})
        nameservers = safe_dns_query(fn -> DNS.get_nameservers(permutation.fqdn) end, [])
        wildcard = safe_dns_query(fn -> DNS.has_wildcard(permutation.fqdn) end, false)

        # Skip HTTP check if no public IPs - don't connect to localhost/private ranges
        server_response = if public_ips != [] do
          try do
            check_server(permutation.fqdn)
          rescue
            _ -> %{status: :error, reason: "check failed"}
          catch
            _, _ -> %{status: :error, reason: "check failed"}
          end
        else
          %{status: :skipped, reason: "no public IPs"}
        end

        # Optional WHOIS enrichment (slower, like dnstwist -w flag)
        whois_data = if include_whois do
          try do
            case Whois.lookup(permutation.fqdn) do
              {:ok, data} -> %{
                registrar: data[:registrar],
                creation_date: data[:creation_date],
                expiration_date: data[:expiration_date],
                source: data[:source]
              }
              {:error, _} -> nil
            end
          rescue
            _ -> nil
          catch
            _, _ -> nil
          end
        else
          nil
        end

        # Optional content similarity (like dnstwist --lsh flag)
        # Skip if no public IPs - don't fetch from localhost/private ranges
        content_hash = if original_content && public_ips != [] do
          try do
            case ContentSimilarity.compare(permutation.fqdn, original_content) do
              {:ok, result} -> result
              _ -> nil
            end
          rescue
            _ -> nil
          catch
            _, _ -> nil
          end
        else
          nil
        end

        # Fuzzy matching scores
        fuzzy = try do
          calculate_fuzzy_scores(domain, permutation.fqdn)
        rescue
          _ -> %{}
        catch
          _, _ -> %{}
        end

        {:ok,
         Map.merge(permutation, %{
           resolvable: true,
           ip_addresses: ips,
           public_ips: public_ips,
           internal_ips: internal_ips,
           ip_flags: ip_flags,
           mx_records: mx_records,
           txt_records: txt_records,
           spf_records: spf_records,
           dmarc: dmarc,
           server_response: server_response,
           nameservers: nameservers,
           wildcard: wildcard,
           whois: whois_data,
           content_hash: content_hash,
           fuzzy: fuzzy
         })}

      {:error, error_message} when is_binary(error_message) ->
        {:error, error_message}

      {:error, _reason} ->
        {:error, :not_resolvable}
    end
  end

  @doc """
  Calculates multiple fuzzy similarity scores between original and permuted domain.

  Returns a map with:
    * :jaro_winkler - Jaro-Winkler distance (0.0-1.0, higher = more similar)
    * :levenshtein - Edit distance (lower = more similar)
    * :keyboard_distance - Weighted distance accounting for keyboard proximity
    * :visual_similarity - Score for visually similar characters (homoglyphs)
  """
  def calculate_fuzzy_scores(original, permuted) do
    # Extract domain name without TLD for comparison
    orig_name = original |> String.split(".") |> List.first()
    perm_name = permuted |> String.split(".") |> List.first()

    %{
      jaro_winkler: String.jaro_distance(original, permuted),
      levenshtein: levenshtein_distance(orig_name, perm_name),
      levenshtein_normalized: normalized_levenshtein(orig_name, perm_name),
      char_diff: count_char_differences(orig_name, perm_name),
      keyboard_proximity: keyboard_proximity_score(orig_name, perm_name)
    }
  end

  # Levenshtein edit distance
  defp levenshtein_distance(s1, s2) do
    s1_chars = String.graphemes(s1)
    s2_chars = String.graphemes(s2)
    _m = length(s1_chars)
    n = length(s2_chars)

    # Initialize first row
    first_row = Enum.to_list(0..n)

    # Compute distance
    {final_row, _} =
      Enum.reduce(Enum.with_index(s1_chars), {first_row, 0}, fn {c1, i}, {prev_row, _} ->
        new_row =
          Enum.reduce(Enum.with_index(s2_chars), {[i + 1], i + 1}, fn {c2, j}, {row, prev_diag} ->
            cost = if c1 == c2, do: 0, else: 1
            [last | _] = row
            above = Enum.at(prev_row, j + 1)
            diag = prev_diag
            val = min(min(last + 1, above + 1), diag + cost)
            {[val | row], Enum.at(prev_row, j + 1)}
          end)

        {Enum.reverse(elem(new_row, 0)), i + 1}
      end)

    List.last(final_row)
  end

  # Normalized Levenshtein (0.0-1.0, higher = more similar)
  defp normalized_levenshtein(s1, s2) do
    max_len = max(String.length(s1), String.length(s2))
    if max_len == 0 do
      1.0
    else
      1.0 - levenshtein_distance(s1, s2) / max_len
    end
  end

  # Count character differences at each position
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
    # QWERTY keyboard layout - adjacent keys get lower penalty
    keyboard_rows = [
      ~w(q w e r t y u i o p),
      ~w(a s d f g h j k l),
      ~w(z x c v b n m)
    ]

    key_positions =
      keyboard_rows
      |> Enum.with_index()
      |> Enum.flat_map(fn {row, row_idx} ->
        row |> Enum.with_index() |> Enum.map(fn {key, col_idx} -> {key, {row_idx, col_idx}} end)
      end)
      |> Map.new()

    orig_chars = String.downcase(original) |> String.graphemes()
    perm_chars = String.downcase(permuted) |> String.graphemes()

    # Compare character by character for same-length portions
    min_len = min(length(orig_chars), length(perm_chars))

    distances =
      Enum.zip(Enum.take(orig_chars, min_len), Enum.take(perm_chars, min_len))
      |> Enum.map(fn {c1, c2} ->
        if c1 == c2 do
          0.0
        else
          case {Map.get(key_positions, c1), Map.get(key_positions, c2)} do
            {nil, _} -> 1.0
            {_, nil} -> 1.0
            {{r1, c1_pos}, {r2, c2_pos}} ->
              # Euclidean distance on keyboard
              :math.sqrt(:math.pow(r1 - r2, 2) + :math.pow(c1_pos - c2_pos, 2)) / 5.0
          end
        end
      end)

    # Add penalty for length difference
    len_diff = abs(length(orig_chars) - length(perm_chars))

    if length(distances) == 0 do
      0.0
    else
      avg_dist = Enum.sum(distances) / length(distances)
      # Normalize to 0-1 range (1 = very similar, 0 = very different)
      max(0.0, 1.0 - avg_dist - len_diff * 0.1)
    end
  end

  # Safe wrapper for DNS queries - returns default on any failure
  defp safe_dns_query(query_fn, default) do
    case query_fn.() do
      {:ok, result} -> result
      {:error, _} -> default
    end
  rescue
    _ -> default
  catch
    _, _ -> default
  end

  @doc """
  Performs a basic HTTP check on a domain's web server.

  ## Parameters
    * domain - String representing the domain to check

  ## Returns
    * map containing server response information or error details

  ## Example
      ```
      iex> DomainTwistex.Utils.check_server("example.com")
      %{
        status_code: "200",
        server: "ECS",
        headers: %{"Server" => "ECS", "Content-Type" => "text/html"}
      }
      ```
  """
  def check_server(domain) do
    case :gen_tcp.connect(
           String.to_charlist(domain),
           80,
           [:binary, packet: 0, active: false],
           10000
         ) do
      {:ok, socket} ->
        http_request = "HEAD / HTTP/1.1\r\nHost: #{domain}\r\nConnection: close\r\n\r\n"
        :gen_tcp.send(socket, http_request)

        case :gen_tcp.recv(socket, 0, 5000) do
          {:ok, response} ->
            :gen_tcp.close(socket)
            parse_response(response)

          {:error, reason} ->
            %{
              hostname: domain,
              status: :error,
              reason: "Failed to receive response: #{inspect(reason)}"
            }
        end

      {:error, reason} ->
        %{
          hostname: domain,
          status: :error,
          reason: "Connection failed: #{inspect(reason)}"
        }
    end
  end

  @doc false
  defp parse_response(response) do
    [status_line | headers] = String.split(response, "\r\n")
    [_http_version, status_code | _] = String.split(status_line, " ")

    headers_map =
      headers
      |> Enum.filter(&(&1 != ""))
      |> Enum.map(fn header ->
        case String.split(header, ": ", parts: 2) do
          [key, value] -> {key, value}
          _ -> nil
        end
      end)
      |> Enum.filter(&(&1 != nil))
      |> Map.new()

    %{
      status_code: status_code,
      server: Map.get(headers_map, "Server", "Unknown"),
      headers: headers_map
    }
  end
end
