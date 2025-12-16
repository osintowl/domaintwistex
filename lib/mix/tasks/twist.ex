defmodule Mix.Tasks.Twist do
  @moduledoc """
  Run DomainTwistex domain permutation scanner.

  ## Usage

      mix twist [options] <domain>

  ## Options

      -c, --concurrency NUM   Number of concurrent checks (default: CPU * 2)
      -t, --timeout MS        Timeout per domain in ms (default: 15000)
      -w, --whois             Enable WHOIS/RDAP lookups (slower)
      --content               Enable content similarity checking (slower)
      --mx-only               Only show domains with MX records
      -f, --format FORMAT     Output format: table, json, csv (default: table)
      -o, --output FILE       Write results to file

  ## Examples

      mix twist example.com
      mix twist -c 100 -w example.com
      mix twist --format json -o results.json example.com
  """

  use Mix.Task

  alias DomainTwistex.Utils
  alias DomainTwistex.Utils.ContentSimilarity

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
          content: :boolean,
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
    include_content = Keyword.get(opts, :content, false)
    format = Keyword.get(opts, :format, "table")
    output_file = Keyword.get(opts, :output)
    mx_only = Keyword.get(opts, :mx_only, false)

    IO.puts("\n#{IO.ANSI.cyan()}DomainTwistex Scanner#{IO.ANSI.reset()}")
    IO.puts(String.duplicate("=", 50))
    IO.puts("Target: #{IO.ANSI.green()}#{domain}#{IO.ANSI.reset()}")
    IO.puts("Concurrency: #{concurrency}")
    IO.puts("Timeout: #{timeout}ms")
    IO.puts("WHOIS: #{if include_whois, do: "enabled", else: "disabled"}")
    IO.puts("Content Hash: #{if include_content, do: "enabled", else: "disabled"}")
    IO.puts(String.duplicate("=", 50))

    # Generate permutations
    IO.write("\nGenerating permutations... ")
    start_gen = System.monotonic_time(:millisecond)
    permutations = Utils.generate_permutations(domain)
    gen_time = System.monotonic_time(:millisecond) - start_gen
    total = length(permutations)
    IO.puts("#{IO.ANSI.green()}#{total}#{IO.ANSI.reset()} permutations (#{gen_time}ms)")

    # Fetch original content if needed
    original_content =
      if include_content do
        IO.write("Fetching original content... ")
        case ContentSimilarity.fetch_original(domain) do
          {:ok, data} ->
            IO.puts("#{IO.ANSI.green()}done#{IO.ANSI.reset()}")
            data
          {:error, reason} ->
            IO.puts("#{IO.ANSI.yellow()}failed: #{inspect(reason)}#{IO.ANSI.reset()}")
            nil
        end
      else
        nil
      end

    IO.puts("\nScanning domains...\n")
    start_time = System.monotonic_time(:millisecond)

    check_opts = [whois: include_whois, original_content: original_content]

    # Collect results with progress
    results =
      permutations
      |> Stream.with_index(1)
      |> Task.async_stream(
        fn {permutation, idx} ->
          result = Utils.check_domain(permutation, domain, check_opts)

          # Print progress
          elapsed = System.monotonic_time(:millisecond) - start_time
          rate = if elapsed > 0, do: Float.round(idx / (elapsed / 1000), 1), else: 0

          case result do
            {:ok, %{resolvable: true} = r} ->
              IO.puts("\r\e[K[+] #{r.fqdn} -> #{Enum.join(r.ip_addresses, ", ")}")
              IO.write("    #{idx}/#{total} (#{rate}/s)")
            _ ->
              if rem(idx, 25) == 0 do
                IO.write("\r\e[K    #{idx}/#{total} (#{rate}/s)")
              end
          end

          {idx, result}
        end,
        ordered: false,
        max_concurrency: concurrency,
        timeout: timeout,
        on_timeout: :kill_task
      )
      |> Stream.filter(fn
        {:ok, {_idx, {:ok, result}}} ->
          cond do
            result.fqdn == domain -> false
            mx_only -> result.resolvable and length(result.mx_records) > 0
            true -> result.resolvable
          end
        _ -> false
      end)
      |> Stream.map(fn {:ok, {_idx, {:ok, result}}} -> result end)
      |> Enum.to_list()

    # Final stats
    elapsed = System.monotonic_time(:millisecond) - start_time

    IO.puts("")
    IO.puts(String.duplicate("=", 50))
    IO.puts("#{IO.ANSI.green()}Scan complete!#{IO.ANSI.reset()}")
    IO.puts("Total checked: #{total}")
    IO.puts("Resolvable found: #{length(results)}")
    IO.puts("Time: #{Float.round(elapsed / 1000, 2)}s")
    rate = if elapsed > 0, do: Float.round(total / (elapsed / 1000), 1), else: 0
    IO.puts("Rate: #{rate} domains/s")
    IO.puts(String.duplicate("=", 50))

    if length(results) > 0 do
      IO.puts("\n#{IO.ANSI.cyan()}Results:#{IO.ANSI.reset()}\n")

      case format do
        "json" -> output_json(results, output_file)
        "csv" -> output_csv(results, output_file)
        _ -> output_table(results, output_file)
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
