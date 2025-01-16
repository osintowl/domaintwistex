defmodule DomainTwistex do
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
    |> generate_permutations()
    |> Task.async_stream(
      &check_domain/1,
      ordered: opts[:ordered],
      max_concurrency: opts[:max_concurrency],
      timeout: opts[:timeout],
      on_timeout: :kill_task
    )
    |> Stream.filter(fn
      # Filter out original domain
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

  defp check_domain(%{fqdn: fqdn} = domain) do
    with {:ok, ips} <- resolve_ips(fqdn),
         mx_records <- get_mx_records(fqdn) do
      {:ok,
       Map.merge(domain, %{
         resolvable: true,
         ip_addresses: ips,
         mx_records: mx_records
       })}
    else
      _ -> {:error, :not_resolvable}
    end
  end

  defp resolve_ips(fqdn) do
    case :inet_res.lookup(String.to_charlist(fqdn), :in, :a) do
      [] ->
        {:error, :no_ips}

      ips when is_list(ips) ->
        {:ok,
         Enum.map(ips, fn ip ->
           ip |> :inet.ntoa() |> to_string()
         end)}

      _ ->
        {:error, :invalid_response}
    end
  end

  defp get_mx_records(fqdn) do
    case :inet_res.lookup(String.to_charlist(fqdn), :in, :mx) do
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
end
