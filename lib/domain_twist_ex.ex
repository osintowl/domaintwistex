defmodule DomainTwistex.Twist do
  alias DomainTwistex.Utils

  @moduledoc """
  Provides high-level domain analysis functionality by combining permutation generation
  with concurrent domain validation checks.

  This module builds upon the DomainTwistex.Utils functionality to provide comprehensive
  domain analysis tools for identifying potential typosquatting and domain abuse scenarios.
  """

  @doc """
  Analyzes a domain by generating permutations and checking them concurrently.

  This function combines permutation generation with comprehensive domain validation,
  running checks in parallel for improved performance. It handles DNS resolution,
  server checking, and MX record validation for each permutation.

  ## Parameters
    * domain - String representing the base domain to analyze (e.g., "example.com")
    * opts - Keyword list of options:
      * max_concurrency: Maximum number of concurrent tasks (default: System.schedulers_online() * 2)
      * timeout: Timeout in milliseconds for each task (default: 5000)
      * ordered: Whether to maintain permutation order in results (default: false)

  ## Returns
    * List of maps, each containing validated domain information:
      * :kind - Type of permutation (e.g., "Homoglyph", "Bitsquatting")
      * :fqdn - Fully qualified domain name
      * :tld - Top-level domain
      * :ip_addresses - List of resolved IP addresses
      * :mx_records - List of MX record information
      * :resolvable - Boolean indicating if domain resolves
      * Additional DNS and server information

  ## Examples
      ```elixir
      # Basic usage
      iex> DomainTwistex.Twist.analyze_domain("google.com")
      [
        %{
          kind: "Tld",
          fqdn: "google.co.uz",
          ip_addresses: ["173.194.219.99", "173.194.219.103"],
          mx_records: [%{priority: 0, server: "."}],
          resolvable: true,
          tld: "co.uz"
        },
        # ... additional results
      ]

      # With custom options
      iex> DomainTwistex.Twist.analyze_domain("example.com", max_concurrency: 50, timeout: 10_000)
      ```

  ## Performance Considerations
    * Higher max_concurrency values can improve speed but may trigger rate limiting
    * Timeout values should be adjusted based on network conditions
    * Setting ordered: true may impact performance for large result sets
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
    |> Utils.generate_permutations()
    |> Task.async_stream(
      fn permutation -> Utils.check_domain(permutation, domain) end,
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

  @doc """
  Filters domain analysis results to return only those with valid MX records.

  This function is particularly useful for identifying potentially malicious domains
  that are set up for email operations, which could be used for phishing attacks.

  ## Parameters
    * domain - String representing the base domain to analyze
    * opts - Keyword list of options (same as analyze_domain/2)

  ## Returns
    * List of maps containing only domains with valid MX records
    * Empty list if no domains with MX records are found or on error

  ## Examples
      ```elixir
      iex> DomainTwistex.Twist.get_live_mx_domains("google.com", max_concurrency: 50)
      [
        %{
          kind: "Tld",
          mx_records: [%{priority: 0, server: "smtp.google.com"}],
          fqdn: "google.lt",
          resolvable: true,
          ip_addresses: ["172.217.215.94"],
          tld: "lt"
        },
        # ... additional results
      ]
      ```

  ## Error Handling
    * Returns an empty list if any errors occur during processing
    * Logs errors to console for debugging purposes
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
