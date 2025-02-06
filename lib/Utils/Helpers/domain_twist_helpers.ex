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
  def validate_domain_resolution(domain, tld) do
    case DNS.resolve_ips(domain) do
      {:ok, %{ips: ips, cname: cname}} ->
        if cname && cname == tld do
          {:error, "tld matches false positive"}
        else
          {:ok, ips}
        end

      {:error, reason} ->
        {:error, reason}
    end
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
  def check_domain(permutation) do
    with {:ok, ips} <- validate_domain_resolution(permutation.fqdn, permutation.tld),
         {:ok, mx_records} <- DNS.get_mx_records(permutation.fqdn),
         {:ok, txt_records} <- DNS.get_txt_records(permutation.fqdn),
         spf_records <- SPF.parse_txt_records({:ok, txt_records}),
         {:ok, dmarc} <- DNS.check_dmarc(permutation.fqdn),
         server_response <- check_server(permutation.fqdn),
         {:ok, nameservers} <- DNS.get_nameservers(permutation.fqdn) do
      {:ok,
       Map.merge(permutation, %{
         resolvable: true,
         ip_addresses: ips,
         mx_records: mx_records,
         txt_records: txt_records,
         spf_records: spf_records,
         dmarc: dmarc,
         server_response: server_response,
         nameservers: nameservers
       })}
    else
      {:error, error_message} when is_binary(error_message) ->
        {:error, error_message}

      _ ->
        {:error, :not_resolvable}
    end
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
