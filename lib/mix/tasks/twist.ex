defmodule Mix.Tasks.Twist do
  @moduledoc """
  Run DomainTwistex domain permutation scanner.

  ## Usage

      mix twist [options] <domain>

  ## Options

      -c, --concurrency NUM   Number of concurrent checks (default: CPU * 2)
      -t, --timeout MS        Timeout per domain in ms (default: 15000)
      -w, --whois             Enable WHOIS/RDAP lookups (slower)
      --mx-only               Only show domains with MX records
      -f, --format FORMAT     Output format: table, json, csv (default: table)
      -o, --output FILE       Write results to file

  ## Examples

      mix twist example.com
      mix twist -c 100 -w example.com
      mix twist --format json -o results.json example.com
  """

  use Mix.Task

  @shortdoc "Scan domain permutations"

  @default_concurrency System.schedulers_online() * 2
  @default_timeout 15_000

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, args, _} =
      OptionParser.parse(args,
        strict: [
          help: :boolean,
          concurrency: :integer,
          timeout: :integer,
          whois: :boolean,
          format: :string,
          output: :string,
          mx_only: :boolean
        ],
        aliases: [
          h: :help,
          c: :concurrency,
          t: :timeout,
          w: :whois,
          o: :output,
          f: :format
        ]
      )

    cond do
      Keyword.get(opts, :help, false) ->
        Mix.shell().info(@moduledoc)

      args == [] ->
        Mix.shell().error("Error: No domain specified\n")
        Mix.shell().info(@moduledoc)

      true ->
        run_scan(opts, hd(args))
    end
  end

  defp run_scan(opts, domain) do
    concurrency = Keyword.get(opts, :concurrency, @default_concurrency)
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    include_whois = Keyword.get(opts, :whois, false)
    format = Keyword.get(opts, :format, "table")
    output_file = Keyword.get(opts, :output)
    mx_only = Keyword.get(opts, :mx_only, false)

    IO.puts("\n#{IO.ANSI.cyan()}DomainTwistex Scanner#{IO.ANSI.reset()}")
    IO.puts(String.duplicate("=", 50))
    IO.puts("Target: #{IO.ANSI.green()}#{domain}#{IO.ANSI.reset()}")
    IO.puts("Concurrency: #{concurrency}")
    IO.puts("Timeout: #{timeout}ms")
    IO.puts("WHOIS: #{if include_whois, do: "enabled", else: "disabled"}")
    IO.puts(String.duplicate("=", 50))

    results = DomainTwistex.Twist.analyze_domain(domain,
      max_concurrency: concurrency,
      timeout: timeout,
      whois: include_whois
    )

    permutations = if mx_only do
      Enum.filter(results.permutations, &(not Enum.empty?(&1.mx_records)))
    else
      Enum.filter(results.permutations, & &1.resolvable)
    end

    IO.puts("\nScanning domains...\n")

    IO.puts("")
    IO.puts(String.duplicate("=", 50))
    IO.puts("#{IO.ANSI.green()}Scan complete!#{IO.ANSI.reset()}")
    IO.puts("Total permutations: #{results.stats.total}")
    IO.puts("Resolvable found: #{results.stats.resolvable}")
    IO.puts(String.duplicate("=", 50))

    if length(permutations) > 0 do
      IO.puts("\n#{IO.ANSI.cyan()}Results:#{IO.ANSI.reset()}\n")

      case format do
        "json" -> output_json(permutations, output_file)
        "csv" -> output_csv(permutations, output_file)
        _ -> output_table(permutations, output_file)
      end
    else
      IO.puts("\nNo resolvable domains found.")
    end
  end

  defp output_table(results, output_file) do
    sorted = Enum.sort_by(results, & &1.kind)

    lines = [
      String.pad_trailing("KIND", 15) <>
        String.pad_trailing("DOMAIN", 40) <>
        String.pad_trailing("IPs", 20) <>
        String.pad_trailing("FLAGS", 15) <>
        "MX",
      String.duplicate("-", 110)
    ]

    result_lines =
      Enum.map(sorted, fn r ->
        ips = (r.public_ips ++ r.internal_ips) |> Enum.take(2) |> Enum.join(", ")
        ips = if length(r.ip_addresses) > 2, do: ips <> "...", else: ips

        flags =
          case r.ip_flags do
            [] -> ""
            f -> f |> Enum.map(&Atom.to_string/1) |> Enum.join(",")
          end

        mx =
          case r.mx_records do
            [] -> "-"
            [first | _] -> first.server |> String.slice(0, 25)
          end

        String.pad_trailing(r.kind, 15) <>
          String.pad_trailing(r.fqdn, 40) <>
          String.pad_trailing(ips, 20) <>
          String.pad_trailing(flags, 15) <>
          mx
      end)

    all_lines = lines ++ result_lines
    output = Enum.join(all_lines, "\n")

    if output_file do
      File.write!(output_file, output)
      IO.puts("Results written to #{output_file}")
    else
      IO.puts(output)
    end

    IO.puts("\nTotal: #{length(results)} domains")
  end

  defp output_json(results, output_file) do
    json = encode_json(results)

    if output_file do
      File.write!(output_file, json)
      IO.puts("Results written to #{output_file}")
    else
      IO.puts(json)
    end
  end

  defp output_csv(results, output_file) do
    headers =
      "kind,fqdn,ip_addresses,public_ips,internal_ips,ip_flags,mx_records,nameservers,resolvable\n"

    rows =
      Enum.map(results, fn r ->
        ips = Enum.join(r.ip_addresses, ";")
        public = Enum.join(r.public_ips, ";")
        internal = Enum.join(r.internal_ips, ";")
        flags = r.ip_flags |> Enum.map(&Atom.to_string/1) |> Enum.join(";")
        mx = r.mx_records |> Enum.map(& &1.server) |> Enum.join(";")
        ns = Enum.join(r.nameservers, ";")

        "#{r.kind},#{r.fqdn},\"#{ips}\",\"#{public}\",\"#{internal}\",\"#{flags}\",\"#{mx}\",\"#{ns}\",#{r.resolvable}"
      end)
      |> Enum.join("\n")

    csv = headers <> rows

    if output_file do
      File.write!(output_file, csv)
      IO.puts("Results written to #{output_file}")
    else
      IO.puts(csv)
    end
  end

  defp encode_json(data) when is_list(data) do
    items = Enum.map(data, &encode_json/1) |> Enum.join(",")
    "[#{items}]"
  end

  defp encode_json(data) when is_map(data) do
    items =
      data
      |> Enum.filter(fn {_k, v} -> v != nil end)
      |> Enum.map(fn {k, v} -> "\"#{k}\":#{encode_json(v)}" end)
      |> Enum.join(",")

    "{#{items}}"
  end

  defp encode_json(data) when is_binary(data) do
    escaped = data |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
    "\"#{escaped}\""
  end

  defp encode_json(data) when is_atom(data), do: "\"#{data}\""
  defp encode_json(data) when is_number(data), do: "#{data}"
  defp encode_json(data) when is_boolean(data), do: "#{data}"
  defp encode_json(nil), do: "null"
end
