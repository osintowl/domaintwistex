defmodule DomainTwistex.Twist do
  import DomainTwistex.Utils
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
    # domain is a string and is passed to generate permutations
    |> DomainTwistex.Utils.generate_permutations()
    |> Task.async_stream(
      # changed this line
      fn permutation -> DomainTwistex.Utils.check_domain(permutation) end,
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
end
