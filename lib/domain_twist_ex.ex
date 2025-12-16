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
      * timeout: Timeout in milliseconds for each task (default: 15000)
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
    alias DomainTwistex.Utils.ContentSimilarity

    opts =
      Keyword.merge(
        [
          max_concurrency: System.schedulers_online() * 2,
          timeout: 15_000,
          ordered: false,
          whois: true,
          content_hash: false
        ],
        opts
      )

    # Fetch original content if content hashing enabled
    original_content = if opts[:content_hash] do
      case ContentSimilarity.fetch_original(domain) do
        {:ok, data} -> data
        {:error, _} -> nil
      end
    else
      nil
    end

    check_opts = [whois: opts[:whois], original_content: original_content]

    domain
    |> Utils.generate_permutations()
    |> Task.async_stream(
      fn permutation -> Utils.check_domain(permutation, domain, check_opts) end,
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
      _e -> []
    end
  end

  # =============================================================================
  # Distributed Scanning
  # =============================================================================

  @doc """
  Returns all permutations for a domain without checking them.

  Useful for splitting work across nodes.

  ## Example
      iex> perms = DomainTwistex.Twist.get_permutations("example.com")
      iex> length(perms)
      4523
  """
  def get_permutations(domain) do
    Utils.generate_permutations(domain)
  end

  @doc """
  Splits permutations into N chunks for distributed processing.

  ## Parameters
    * domain - The domain to generate permutations for
    * num_chunks - Number of chunks (typically = number of nodes)

  ## Returns
    List of {chunk_index, permutations} tuples

  ## Example
      iex> chunks = DomainTwistex.Twist.split_for_nodes("example.com", 3)
      iex> length(chunks)
      3
      iex> {index, perms} = hd(chunks)
  """
  def split_for_nodes(domain, num_chunks) do
    domain
    |> Utils.generate_permutations()
    |> Enum.chunk_every(ceil(length(Utils.generate_permutations(domain)) / num_chunks))
    |> Enum.with_index()
    |> Enum.map(fn {chunk, idx} -> {idx, chunk} end)
  end

  @doc """
  Analyzes a specific chunk of permutations.

  Use this on each node to process its assigned chunk.

  ## Parameters
    * permutations - List of permutation maps to check
    * domain - Original domain (for distance calculation)
    * opts - Same options as analyze_domain/2

  ## Example
      # On node 1:
      chunks = DomainTwistex.Twist.split_for_nodes("abbvie.com", 3)
      {0, my_chunk} = Enum.at(chunks, 0)
      results = DomainTwistex.Twist.analyze_chunk(my_chunk, "abbvie.com")
  """
  def analyze_chunk(permutations, domain, opts \\ []) do
    alias DomainTwistex.Utils.ContentSimilarity

    opts =
      Keyword.merge(
        [
          max_concurrency: System.schedulers_online() * 2,
          timeout: 15_000,
          ordered: false,
          whois: true,
          content_hash: false
        ],
        opts
      )

    # Fetch original content if content hashing enabled
    original_content = if opts[:content_hash] do
      case ContentSimilarity.fetch_original(domain) do
        {:ok, data} -> data
        {:error, _} -> nil
      end
    else
      nil
    end

    check_opts = [whois: opts[:whois], original_content: original_content]

    permutations
    |> Task.async_stream(
      fn permutation -> Utils.check_domain(permutation, domain, check_opts) end,
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
  Distributes analysis across connected Erlang nodes.

  Automatically splits work across all connected nodes + current node.

  ## Parameters
    * domain - Domain to analyze
    * opts - Options:
      * :nodes - List of nodes to use (default: [node() | Node.list()])
      * :max_concurrency - Per-node concurrency
      * :timeout - Per-domain timeout

  ## Example
      # First connect nodes:
      Node.connect(:"node2@192.168.1.10")
      Node.connect(:"node3@192.168.1.11")

      # Then distribute:
      results = DomainTwistex.Twist.analyze_distributed("abbvie.com")

  ## Returns
    Combined results from all nodes
  """
  def analyze_distributed(domain, opts \\ []) do
    nodes = Keyword.get(opts, :nodes, [node() | Node.list()])
    num_nodes = length(nodes)

    if num_nodes == 0 do
      raise "No nodes available for distributed analysis"
    end

    chunks = split_for_nodes(domain, num_nodes)
    chunk_opts = Keyword.drop(opts, [:nodes])

    tasks =
      chunks
      |> Enum.zip(nodes)
      |> Enum.map(fn {{_idx, perms}, target_node} ->
        Task.async(fn ->
          :erpc.call(target_node, __MODULE__, :analyze_chunk, [perms, domain, chunk_opts], :infinity)
        end)
      end)

    tasks
    |> Task.await_many(:infinity)
    |> List.flatten()
  end

  @doc """
  Returns info about the current distributed setup.

  ## Example
      iex> DomainTwistex.Twist.cluster_info()
      %{
        current_node: :"node1@127.0.0.1",
        connected_nodes: [:"node2@127.0.0.1"],
        total_nodes: 2
      }
  """
  def cluster_info do
    %{
      current_node: node(),
      connected_nodes: Node.list(),
      total_nodes: length(Node.list()) + 1
    }
  end
end
