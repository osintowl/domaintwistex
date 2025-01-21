defmodule DomainTwistex.Twist do
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
     iex(1)> DomainTwistex.generate_permutations("google.com")
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

  @doc group: "2. Elixir Functions"
  @doc """
  Analyzes a domain by generating permutations and checking them concurrently.

  ## Parameters
    * domain - The base domain string to analyze
    * opts - Optional keyword list of settings:
      * max_concurrency: Maximum number of concurrent tasks (default: System.schedulers_online() * 2)
      * timeout: Timeout in milliseconds for each task (default: 2000)
      * ordered: Whether results should maintain order (default: false)

  ## Returns
    List of successful domain check results

  ## Examples
    
    ```
    iex(2)> DomainTwistex.analyze_domain("google.com")
    [
      %{
         kind: "Tld",
         fqdn: "google.co.uz",
         ip_addresses: ["173.194.219.99", "173.194.219.103", "173.194.219.147",
         "173.194.219.104", "173.194.219.105", "173.194.219.106"],
         mx_records: [%{priority: 0, server: "."}],
         resolvable: true,
         tld: "co.uz"
         },
      %{
        kind: "Bitsquatting",
        fqdn: "gooogle.com",
        ip_addresses: ["64.233.185.104", "64.233.185.106", "64.233.185.99",
        "64.233.185.147", "64.233.185.105", "64.233.185.103"],
        mx_records: [%{priority: 0, server: "."}],
        resolvable: true,
        tld: "com"
        },...]
        
    ```
  """
    def analyze_domain(domain, opts \\ []) do
      opts =
        Keyword.merge(
          [
            max_concurrency: System.schedulers_online() * 2,
            timeout: 5_000,
            ordered: false
          ],
          opts
        )
      domain
      #domain is a string and is passed to generate permutations
      |> generate_permutations()
      |> Task.async_stream(
        fn permutation -> check_domain(permutation) end,  # changed this line
        ordered: opts[:ordered],
        max_concurrency: opts[:max_concurrency],
        timeout: opts[:timeout],
        on_timeout: :kill_task
      )
      |> Stream.filter(fn
        {:ok, {:ok, result}} -> result.fqdn != domain
        _ -> false
      end)
      |> Stream.map(fn {:ok, {:ok, result}} -> result end)
      |> Enum.into([])
  end

  @doc group: "2. Elixir Functions"
  @doc """
  Filters domains to return only those with valid MX records.

  ## Parameters
    * domain - The domain to analyze

  ## Returns
    List of domain results that have non-empty MX records

  ## Examples

  ```
     iex(3)> DomainTwistex.get_live_mx_domains("google.com", max_concurrency: 50)
     [%{
        kind: "Tld",
        mx_records: [%{priority: 0, server: "smtp.google.com"}],
        fqdn: "google.lt",
        resolvable: true,
        ip_addresses: ["172.217.215.94"],
        tld: "lt"
        },
        %{
        kind: "Tld",
        mx_records: [%{priority: 0, server: "smtp.google.com"}],
        fqdn: "google.rs",
        resolvable: true,
        ip_addresses: ["142.250.9.94"],
        tld: "rs"
        },...]
  ```
  """
  def get_live_mx_domains(domain, opts \\ []) do
    try do
      domain
      |> analyze_domain(opts)
      |> Enum.filter(&(not Enum.empty?(&1.mx_records)))
    rescue
      e ->
        IO.puts("Error in get_mx_records: #{inspect(e)}")
        []
    end
  end

  
  defp check_domain(permutation) do
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

    defp resolve_ips(perm_domain, perm_tld) do
    case :inet_res.lookup(String.to_charlist(perm_domain), :in, :cname) do
      [cname] ->
        # Convert CNAME charlist to string and compare with TLD
        if to_string(cname) == perm_tld do
          {:error, "tld matches false positive"}
        else
          # If CNAME doesn't match TLD, proceed with A record lookup
          case :inet_res.lookup(String.to_charlist(perm_domain), :in, :a) do
            [] -> {:error, :no_ips}
            ips when is_list(ips) ->
              {:ok, Enum.map(ips, fn ip -> ip |> :inet.ntoa() |> to_string() end)}
            _ -> {:error, :invalid_response}
          end
        end
      
      [] ->
        # No CNAME, just check A records
        case :inet_res.lookup(String.to_charlist(perm_domain), :in, :a) do
          [] -> {:error, :no_ips}
          ips when is_list(ips) ->
            {:ok, Enum.map(ips, fn ip -> ip |> :inet.ntoa() |> to_string() end)}
          _ -> {:error, :invalid_response}
        end
  
      _ ->
        {:error, :invalid_response}
    end
  end


  defp get_nameservers(perm_domain) do
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

  defp get_mx_records(perm_domain) do
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

  defp get_txt_records(perm_domain) do
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

  defp check_server(perm_domain) do
    case :gen_tcp.connect(String.to_charlist(perm_domain), 80, [:binary, packet: 0, active: false], 10000) do
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
