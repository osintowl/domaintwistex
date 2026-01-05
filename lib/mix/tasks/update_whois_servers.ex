defmodule Mix.Tasks.UpdateWhoisServers do
  @moduledoc """
  Fetches the latest WHOIS server mappings from IANA-sourced data.

  ## Usage

      mix update_whois_servers

  This task downloads the whois.conf.baseline file from the iana-whois-conf
  project, which scrapes WHOIS server information directly from IANA's
  official TLD pages at https://www.iana.org/domains/root/db/

  The resulting data is saved to priv/whois_servers.json and compiled into
  the application at build time.

  ## Source

  Data is sourced from: https://github.com/roycewilliams/iana-whois-conf
  Which scrapes: https://www.iana.org/domains/root/db/{tld}.html
  """

  use Mix.Task

  @shortdoc "Update WHOIS server mappings from IANA"

  @iana_whois_conf_url "https://raw.githubusercontent.com/roycewilliams/iana-whois-conf/master/whois.conf.baseline"
  @output_path "priv/whois_servers.json"

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    Mix.shell().info("Fetching WHOIS servers from IANA-sourced data...")
    Mix.shell().info("Source: #{@iana_whois_conf_url}")

    case fetch_and_parse() do
      {:ok, servers} ->
        write_json(servers)
        Mix.shell().info("Successfully updated #{map_size(servers)} WHOIS server mappings")
        Mix.shell().info("Output: #{@output_path}")

      {:error, reason} ->
        Mix.shell().error("Failed to update WHOIS servers: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end

  defp fetch_and_parse do
    case Req.get(@iana_whois_conf_url, receive_timeout: 30_000) do
      {:ok, %Req.Response{status: 200, body: body}} ->
        servers = parse_whois_conf(body)
        {:ok, servers}

      {:ok, %Req.Response{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_whois_conf(content) do
    content
    |> String.split("\n")
    |> Enum.reduce(%{}, fn line, acc ->
      # Format: \.tld$ whois.server.com
      case Regex.run(~r/^\\\.([a-z0-9-]+)\$\s+(.+)$/, String.trim(line)) do
        [_, tld, server] ->
          Map.put(acc, tld, String.trim(server))

        nil ->
          acc
      end
    end)
  end

  defp write_json(servers) do
    # Ensure priv directory exists
    File.mkdir_p!("priv")

    json = encode_json(servers)
    File.write!(@output_path, json)
  end

  defp encode_json(map) when is_map(map) do
    entries =
      map
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {k, v} -> "  #{inspect(k)}: #{inspect(v)}" end)
      |> Enum.join(",\n")

    "{\n#{entries}\n}\n"
  end
end
