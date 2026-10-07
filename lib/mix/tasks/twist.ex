defmodule Mix.Tasks.Twist do
  @moduledoc """
  Run DomainTwistex domain permutation scanner.

  ## Usage

      mix twist [options] <domain>

  ## Options

      -c, --concurrency NUM   Concurrent enrichments (default: max(CPU * 4, 16))
      --dns-concurrency NUM   Concurrent DNS existence probes (default: 200, capped at 40 per resolver)
      -t, --timeout MS        Enrichment budget per domain in ms (default: 15000)
      --dns-timeout MS        Timeout per DNS query in ms (default: 5000)
      -n, --nameserver IP     Resolver to use (repeatable). Default: 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.10
      --system-dns            Use the system resolver instead of the public pool
      --no-whois              Skip WHOIS/RDAP lookups (faster; on by default)
      --mx-only               Only show domains with MX records
      --priority-keywords     Use only high-priority phishing keywords (faster)
      --all-tlds              Use the full public suffix list for TLD swaps (~7K)
      --faux-tld              Include FauxTld permutations
      --vowel-shuffle         Include VowelShuffle permutations
      -k, --kinds LIST        Only these kinds, comma-separated (e.g. homoglyph,bitsquatting)
      -f, --format FORMAT     Output format: table, json, csv (default: table)
      -o, --output FILE       Write results to file

  ## Examples

      mix twist example.com
      mix twist -c 100 --no-whois example.com
      mix twist -n 1.1.1.1 -n 8.8.8.8 example.com
      mix twist --system-dns example.com
      mix twist --format json -o results.json example.com
      mix twist --mx-only --priority-keywords example.com
      mix twist -k homoglyph,bitsquatting example.com

  """

  use Mix.Task

  @shortdoc "Scan domain permutations for typosquatting detection"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, args, invalid} =
      OptionParser.parse(args,
        strict: [
          help: :boolean,
          concurrency: :integer,
          dns_concurrency: :integer,
          timeout: :integer,
          dns_timeout: :integer,
          nameserver: :keep,
          system_dns: :boolean,
          whois: :boolean,
          format: :string,
          output: :string,
          mx_only: :boolean,
          priority_keywords: :boolean,
          all_tlds: :boolean,
          faux_tld: :boolean,
          vowel_shuffle: :boolean,
          kinds: :string
        ],
        aliases: [
          h: :help,
          c: :concurrency,
          t: :timeout,
          n: :nameserver,
          k: :kinds,
          o: :output,
          f: :format
        ]
      )

    cond do
      Keyword.get(opts, :help, false) ->
        Mix.shell().info(@moduledoc)

      invalid != [] ->
        Mix.shell().error("Invalid options: #{Enum.map_join(invalid, ", ", &elem(&1, 0))}\n")
        Mix.shell().info(@moduledoc)

      args == [] ->
        Mix.shell().error("Error: No domain specified\n")
        Mix.shell().info(@moduledoc)

      true ->
        run_scan(opts, hd(args))
    end
  end

  defp run_scan(opts, domain) do
    defaults = DomainTwistex.Twist.default_opts()
    format = Keyword.get(opts, :format, "table")
    output_file = Keyword.get(opts, :output)
    mx_only = Keyword.get(opts, :mx_only, false)
    nameservers = Keyword.get_values(opts, :nameserver)
    system_dns = Keyword.get(opts, :system_dns, false)

    scan_opts =
      [
        max_concurrency: Keyword.get(opts, :concurrency, defaults[:max_concurrency]),
        dns_concurrency: Keyword.get(opts, :dns_concurrency, defaults[:dns_concurrency]),
        timeout: Keyword.get(opts, :timeout, defaults[:timeout]),
        dns_timeout: Keyword.get(opts, :dns_timeout, defaults[:dns_timeout]),
        whois: Keyword.get(opts, :whois, defaults[:whois]),
        priority_keywords_only: Keyword.get(opts, :priority_keywords, false),
        tlds: if(Keyword.get(opts, :all_tlds, false), do: :all, else: :common),
        faux_tld: Keyword.get(opts, :faux_tld, false),
        vowel_shuffle: Keyword.get(opts, :vowel_shuffle, false),
        kinds: parse_kinds(Keyword.get(opts, :kinds))
      ]

    scan_opts =
      cond do
        nameservers != [] -> Keyword.put(scan_opts, :nameservers, nameservers)
        system_dns -> Keyword.put(scan_opts, :nameservers, nil)
        true -> scan_opts
      end

    resolvers =
      case Keyword.get(scan_opts, :nameservers, :default) do
        :default -> Enum.join(DomainTwistex.DNS.public_nameservers(), ", ")
        nil -> "system"
        list -> Enum.join(list, ", ")
      end

    IO.puts("\n#{IO.ANSI.cyan()}DomainTwistex Scanner#{IO.ANSI.reset()}")
    IO.puts(String.duplicate("=", 50))
    IO.puts("Target: #{IO.ANSI.green()}#{domain}#{IO.ANSI.reset()}")

    IO.puts(
      "Concurrency: #{scan_opts[:max_concurrency]} (DNS: #{DomainTwistex.Twist.dns_probe_concurrency(scan_opts)})"
    )

    IO.puts("Timeout: #{scan_opts[:timeout]}ms")
    IO.puts("Resolvers: #{resolvers}")
    IO.puts("TLDs: #{scan_opts[:tlds]}")
    IO.puts("WHOIS: #{if scan_opts[:whois], do: "enabled", else: "disabled"}")
    IO.puts("MX Only: #{if mx_only, do: "yes", else: "no"}")
    IO.puts(String.duplicate("=", 50))
    IO.puts("\nGenerating permutations and scanning...\n")

    results = DomainTwistex.analyze(domain, scan_opts)
    stats = results.stats

    permutations = Enum.filter(results.permutations, &(not mx_only or &1.mx_records != []))

    IO.puts(String.duplicate("=", 50))
    IO.puts("#{IO.ANSI.green()}Scan complete!#{IO.ANSI.reset()}")
    IO.puts("Domain: #{results.domain}")
    IO.puts("Total permutations: #{stats.total}")
    IO.puts("Registered: #{stats.found} (resolvable: #{stats.resolvable}, with MX: #{stats.mx})")
    IO.puts("Filtered wildcards: #{stats.wildcard_filtered}")
    IO.puts("DNS errors: #{stats.dns_errors}, timeouts: #{stats.timeouts}")
    IO.puts("Elapsed time: #{format_elapsed(stats.elapsed_ms)}")
    IO.puts(String.duplicate("=", 50))

    if permutations != [] do
      IO.puts("\n#{IO.ANSI.cyan()}Results:#{IO.ANSI.reset()}\n")

      case format do
        "json" -> output_json(permutations, output_file)
        "csv" -> output_csv(permutations, output_file)
        _ -> output_table(permutations, output_file)
      end
    else
      IO.puts("\nNo matching domains found.")
    end
  end

  defp parse_kinds(nil), do: nil

  defp parse_kinds(kinds) do
    valid = MapSet.new(DomainTwistex.Permutate.kinds())

    kinds
    |> String.split(",", trim: true)
    |> Enum.map(&(&1 |> String.trim() |> Macro.camelize()))
    |> tap(fn names ->
      case Enum.reject(names, &MapSet.member?(valid, &1)) do
        [] -> :ok
        bad -> Mix.raise("Unknown kinds: #{Enum.join(bad, ", ")}")
      end
    end)
  end

  defp output_table(results, output_file) do
    header =
      String.pad_trailing("KIND", 15) <>
        String.pad_trailing("DOMAIN", 40) <>
        String.pad_trailing("IPs", 34) <>
        "MX"

    result_lines =
      Enum.map(results, fn r ->
        ips = r.ip_addresses |> Enum.take(2) |> Enum.join(", ")
        ips = if length(r.ip_addresses) > 2, do: ips <> "...", else: ips

        mx =
          case r.mx_records do
            [] -> "-"
            [first | _] -> String.slice(first.server, 0, 25)
          end

        name = if r[:unicode], do: "#{r.unicode} (#{r.fqdn})", else: r.fqdn

        String.pad_trailing(r.kind, 15) <>
          String.pad_trailing(name, 40) <>
          String.pad_trailing(ips, 34) <>
          mx
      end)

    write_output(
      Enum.join([header, String.duplicate("-", 120) | result_lines], "\n"),
      output_file
    )

    IO.puts("\nTotal: #{length(results)} domains")
  end

  defp output_json(results, output_file) do
    results
    |> Jason.encode!(pretty: true)
    |> write_output(output_file)
  end

  @csv_headers ~w(kind fqdn unicode ip_addresses public_ips internal_ips ip_flags
                  mx_records nameservers http_status https_status title tls_issuer
                  tls_age_days registrar creation_date)

  defp output_csv(results, output_file) do
    rows =
      Enum.map(results, fn r ->
        server = if is_map(r.server_response), do: r.server_response, else: %{}
        http = Map.get(server, :http) || %{}
        https = Map.get(server, :https) || %{}
        tls = Map.get(server, :tls) || %{}
        whois = r.whois || %{}

        [
          r.kind,
          r.fqdn,
          r[:unicode],
          Enum.join(r.ip_addresses, ";"),
          Enum.join(r.public_ips, ";"),
          Enum.join(r.internal_ips, ";"),
          Enum.join(r.ip_flags, ";"),
          r.mx_records |> Enum.map(& &1.server) |> Enum.join(";"),
          Enum.join(r.nameservers, ";"),
          http[:status_code],
          https[:status_code],
          https[:title] || http[:title],
          tls[:issuer],
          tls[:age_days],
          whois[:registrar],
          whois[:creation_date]
        ]
        |> Enum.map_join(",", &csv_field/1)
      end)

    write_output(Enum.join([Enum.join(@csv_headers, ",") | rows], "\n"), output_file)
  end

  defp csv_field(nil), do: ""

  defp csv_field(value) do
    value = to_string(value)

    if String.contains?(value, [",", "\"", "\n", "\r"]),
      do: "\"" <> String.replace(value, "\"", "\"\"") <> "\"",
      else: value
  end

  defp write_output(output, nil), do: IO.puts(output)

  defp write_output(output, file) do
    File.write!(file, output)
    IO.puts("Results written to #{file}")
  end

  defp format_elapsed(ms) when ms < 1_000, do: "#{ms}ms"
  defp format_elapsed(ms) when ms < 60_000, do: "#{Float.round(ms / 1_000, 1)}s"

  defp format_elapsed(ms) do
    minutes = div(ms, 60_000)
    seconds = Float.round(rem(ms, 60_000) / 1_000, 1)
    "#{minutes}m #{seconds}s"
  end
end
