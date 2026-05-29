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

  Generates all permutations for the given domain, then resolves each one with
  parallel DNS, WHOIS, and server checks. Filters out the original domain and
  wildcard-only results (wildcard + no public IPs).

  ## Parameters
    * domain - String representing the base domain to analyze (e.g., "example.com")
    * opts - Keyword list of options:
      * :max_concurrency - Maximum number of concurrent tasks (default: System.schedulers_online() * 2)
      * :timeout - Timeout in milliseconds for each task (default: 15000)
      * :ordered - Whether to maintain permutation order in results (default: false)
      * :whois - Enable WHOIS/RDAP lookups (default: true)

  ## Returns
    A map with the following keys:
      * :domain - The original domain string
      * :original - Resolved baseline data for the original domain (without fuzzy scores)
      * :permutations - List of resolvable permutation results (excluding wildcards with no public IPs)
      * :stats - Map with :total (permutations generated) and :resolvable (permutations that resolved)

  ## Examples
      ```elixir
      iex> DomainTwistex.Twist.analyze_domain("example.com")
      %{
        domain: "example.com",
        original: %{fqdn: "example.com", resolvable: true, ...},
        permutations: [
          %{kind: "Tld", fqdn: "example.co.uk", ip_addresses: [...], ...},
          ...
        ],
        stats: %{total: 9541, resolvable: 42}
      }

      # With custom options
      iex> DomainTwistex.Twist.analyze_domain("example.com", max_concurrency: 50, whois: true)
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
          timeout: 15_000,
          ordered: false,
          whois: true
        ],
        opts
      )

    check_opts = [whois: opts[:whois]]

    # Resolve original domain and store its baseline data
    original = resolve_original(domain, check_opts)

    all_permutations = Utils.generate_permutations(domain)
    total_generated = length(all_permutations)

    permutations =
      all_permutations
      |> Task.async_stream(
        fn permutation -> Utils.check_domain(permutation, domain, check_opts) end,
        ordered: opts[:ordered],
        max_concurrency: opts[:max_concurrency],
        timeout: opts[:timeout],
        on_timeout: :kill_task
      )
      |> Stream.filter(fn
        {:ok, {:ok, result}} ->
          result.fqdn != domain and not (result.wildcard == true and result.public_ips == [])
        _ -> false
      end)
      |> Stream.map(fn {:ok, {:ok, result}} -> result end)
      |> Enum.into([])

    %{
      domain: domain,
      original: original,
      permutations: permutations,
      stats: %{
        total: total_generated,
        resolvable: length(permutations)
      }
    }
  end

  defp resolve_original(domain, check_opts) do
    permutation = %{fqdn: domain, tld: domain |> String.split(".", parts: 2) |> List.last()}

    case Utils.check_domain(permutation, domain, check_opts) do
      {:ok, result} -> Map.delete(result, :fuzzy)
      {:error, _} -> %{fqdn: domain, resolvable: false}
    end
  end

  @doc """
  Filters domain analysis results to return only permutations with valid MX records.

  This function is particularly useful for identifying potentially malicious domains
  that are set up for email operations, which could be used for phishing attacks.

  ## Parameters
    * domain - String representing the base domain to analyze
    * opts - Keyword list of options (same as analyze_domain/2)

  ## Returns
    A map with the same shape as analyze_domain/2, but permutations filtered to
    only those with MX records. Stats includes :mx_count.

  ## Examples
      ```elixir
      iex> DomainTwistex.Twist.get_live_mx_domains("google.com")
      %{
        domain: "google.com",
        original: %{...},
        permutations: [%{kind: "Tld", mx_records: [%{priority: 0, server: "smtp.google.com"}], ...}],
        stats: %{total: 9541, resolvable: 42, mx_count: 12}
      }
      ```
  """
  def get_live_mx_domains(domain, opts \\ []) do
    try do
      result = analyze_domain(domain, opts)
      mx_only = Enum.filter(result.permutations, &(not Enum.empty?(&1.mx_records)))
      %{result | permutations: mx_only, stats: Map.put(result.stats, :mx_count, length(mx_only))}
    rescue
      _e -> %{domain: domain, original: nil, permutations: [], stats: %{}}
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
    opts =
      Keyword.merge(
        [
          max_concurrency: System.schedulers_online() * 2,
          timeout: 15_000,
          ordered: false,
          whois: true
        ],
        opts
      )

    check_opts = [whois: opts[:whois]]

    permutations
    |> Task.async_stream(
      fn permutation -> Utils.check_domain(permutation, domain, check_opts) end,
      ordered: opts[:ordered],
      max_concurrency: opts[:max_concurrency],
      timeout: opts[:timeout],
      on_timeout: :kill_task
    )
    |> Stream.filter(fn
      {:ok, {:ok, result}} ->
        result.fqdn != domain and not (result.wildcard == true and result.public_ips == [])
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
