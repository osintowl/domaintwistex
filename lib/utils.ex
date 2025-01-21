defmodule DomainTwistex.Utils do
  use Rustler, otp_app: :domaintwistex, crate: "domaintwistex"

  @moduledoc """
  DomainTwistEx provides domain permutation generation using Rust NIFs.

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
  The actual implementation is in Rust and loaded at runtime.

  ## Attribution
  This NIF wraps functionality from the Twistrs library:
  https://github.com/haveibeensquatted/twistrs

  ## Prerequisites
  Requires:
  - Rust toolchain installed (rustc, cargo)
  - Proper NIF compilation setup in mix.exs
  - `native/domaintwistex` Rust project properly configured

  ## Parameters
    * domain - String representing the domain to generate permutations for

  ## Returns
    List of generated domain permutation strings

  ## Examples
     
     ```
     iex(1)> DomainTwistex.Utils.generate_permutations("google.com")
     [ %{kind: "Keyword", fqdn: "servicegoogle.com", tld: "com"},
     %{kind: "Homoglyph", fqdn: "ğöögle.com", tld: "com"},
     %{kind: "Homoglyph", fqdn: "ğöogle.com", tld: "com"},
     %{kind: "Tld", fqdn: "google.cc", tld: "cc"},
     %{kind: "Homoglyph", fqdn: "ğoơgle.com", tld: "com"},
     %{kind: "Homoglyph", fqdn: "goóglë.com", tld: "com"}, ...]
     ``` 
  ## Runtime
  This function will raise an error if:
  - The NIF library fails to load
  - Rust/Cargo is not installed during compilation
  """
  def generate_permutations(_domain), do: :erlang.nif_error(:nif_not_loaded)

  def check_domain(permutation) do
    with {:ok, ips} <- resolve_ips(permutation.fqdn, permutation.tld),
         mx_records <- get_mx_records(permutation.fqdn),
         txt_records <- get_txt_records(permutation.fqdn),
         server_response <- check_server(permutation.fqdn),
         {:ok, ns_info} <- get_nameservers(permutation.fqdn) do
      {:ok,
       Map.merge(permutation, %{
         resolvable: true,
         ip_addresses: ips,
         mx_records: mx_records,
         txt_records: txt_records,
         server_response: server_response,
         nameservers: ns_info.nameservers
       })}
    else
      {:error, error_message} when is_binary(error_message) ->
        {:error, error_message}

      _ ->
        {:error, :not_resolvable}
    end
  end

  def resolve_ips(perm_domain, perm_tld) do
    case :inet_res.lookup(String.to_charlist(perm_domain), :in, :cname) do
      [cname] ->
        # Convert CNAME charlist to string and compare with TLD
        if to_string(cname) == perm_tld do
          {:error, "tld matches false positive"}
          IO.puts(perm_tld)
        else
          # If CNAME doesn't match TLD, proceed with A record lookup
          case :inet_res.lookup(String.to_charlist(perm_domain), :in, :a) do
            [] ->
              {:error, :no_ips}

            ips when is_list(ips) ->
              {:ok, Enum.map(ips, fn ip -> ip |> :inet.ntoa() |> to_string() end)}

            _ ->
              {:error, :invalid_response}
          end
        end

      [] ->
        # No CNAME, just check A records
        case :inet_res.lookup(String.to_charlist(perm_domain), :in, :a) do
          [] ->
            {:error, :no_ips}

          ips when is_list(ips) ->
            {:ok, Enum.map(ips, fn ip -> ip |> :inet.ntoa() |> to_string() end)}

          _ ->
            {:error, :invalid_response}
        end

      _ ->
        {:error, :invalid_response}
    end
  end

  def get_nameservers(perm_domain) do
    try do
      # Using :inet_res from Erlang's standard library
      case :inet_res.lookup(String.to_charlist(perm_domain), :in, :ns) do
        [] ->
          {:error, "No nameservers found"}

        nameservers when is_list(nameservers) ->
          formatted_ns =
            nameservers
            |> Enum.map(fn ns ->
              ns
              |> to_string()
              |> String.trim_trailing(".")
            end)

          {:ok, %{nameservers: formatted_ns}}

        {:error, reason} ->
          {:error, "DNS lookup failed: #{reason}"}
      end
    rescue
      e -> {:error, "Nameserver lookup error: #{Exception.message(e)}"}
    end
  end

  def get_mx_records(perm_domain) do
    case :inet_res.lookup(String.to_charlist(perm_domain), :in, :mx) do
      [] ->
        []

      mx_records when is_list(mx_records) ->
        Enum.map(mx_records, fn {priority, server} ->
          %{
            priority: priority,
            # Using List.to_string instead of :inet.ntoa
            server: server |> List.to_string()
          }
        end)

      _ ->
        []
    end
  rescue
    e ->
      IO.puts("Error in get_mx_records: #{inspect(e)}")
      []
  end

  def get_txt_records(perm_domain) do
    case :inet_res.resolve(String.to_charlist(perm_domain), :in, :txt) do
      {:ok, dns_response} ->
        # Get the responses section from the DNS response tuple
        responses = elem(dns_response, 3)

        # Map over each response and extract the TXT record
        Enum.map(responses, fn response ->
          # Extract the actual record content (at position 6 in the tuple)
          record = elem(response, 6)
          # Convert the charlist to string
          List.to_string(record)
        end)

      {:error, reason} ->
        {:error, "Failed to retrieve TXT records: #{inspect(reason)}"}
    end
  end

  def check_server(perm_domain) do
    case :gen_tcp.connect(
           String.to_charlist(perm_domain),
           80,
           [:binary, packet: 0, active: false],
           10000
         ) do
      {:ok, socket} ->
        http_request = "HEAD / HTTP/1.1\r\nHost: #{perm_domain}\r\nConnection: close\r\n\r\n"
        :gen_tcp.send(socket, http_request)

        case :gen_tcp.recv(socket, 0, 5000) do
          {:ok, response} ->
            :gen_tcp.close(socket)
            parse_response(response)

          {:error, reason} ->
            %{
              hostname: perm_domain,
              status: :error,
              reason: "Failed to receive response: #{inspect(reason)}"
            }
        end

      {:error, reason} ->
        %{
          hostname: perm_domain,
          status: :error,
          reason: "Connection failed: #{inspect(reason)}"
        }
    end
  end

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

    # Extract server version from headers
    server_info = Map.get(headers_map, "Server", "Unknown")

    %{
      status_code: status_code,
      server: server_info,
      headers: headers_map
    }
  end
end
