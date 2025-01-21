defmodule DomainTwistex.DNS do
  @moduledoc """
  Provides pure DNS query operations for domain names.
  Handles various DNS record types including A, CNAME, MX, TXT, and NS records.
  All functions use Erlang's :inet_res module for DNS resolution.
  """

  @doc """
  Resolves IP addresses for a given domain, handling both A and CNAME records.

  ## Parameters
    * domain - String representing the domain to resolve

  ## Returns
    * `{:ok, %{ips: [string], cname: string | nil}}` - Resolved DNS information
    * `{:error, :no_records}` - When no records are found
    * `{:error, :invalid_response}` - When DNS lookup returns invalid response

  ## Example
      ```
      iex> DomainTwistex.DNS.resolve_ips("example.com")
      {:ok, %{ips: ["93.184.216.34"], cname: nil}}
      ```
  """
  def resolve_ips(domain) do
    cname_result = :inet_res.lookup(String.to_charlist(domain), :in, :cname)
    a_records = lookup_a_records(domain)

    case {cname_result, a_records} do
      {[], {:ok, ips}} ->
        {:ok, %{ips: ips, cname: nil}}

      {[cname], {:ok, ips}} ->
        {:ok, %{ips: ips, cname: to_string(cname)}}

      {_, {:error, reason}} ->
        {:error, reason}

      _ ->
        {:error, :invalid_response}
    end
  end

  @doc """
  Retrieves nameserver information for a domain.

  ## Parameters
    * domain - String representing the domain to query

  ## Returns
    * `{:ok, [string]}` - List of nameserver hostnames
    * `{:error, string}` - Error message if lookup fails

  ## Example
      ```
      iex> DomainTwistex.DNS.get_nameservers("example.com")
      {:ok, ["ns1.example.com", "ns2.example.com"]}
      ```
  """
  def get_nameservers(domain) do
    try do
      case :inet_res.lookup(String.to_charlist(domain), :in, :ns) do
        [] ->
          {:error, "No nameservers found"}

        nameservers when is_list(nameservers) ->
          formatted_ns =
            nameservers
            |> Enum.map(&(to_string(&1) |> String.trim_trailing(".")))

          {:ok, formatted_ns}

        {:error, reason} ->
          {:error, "DNS lookup failed: #{reason}"}
      end
    rescue
      e -> {:error, "Nameserver lookup error: #{Exception.message(e)}"}
    end
  end

  @doc """
  Retrieves MX (Mail Exchange) records for a domain.

  ## Parameters
    * domain - String representing the domain to query

  ## Returns
    * `{:ok, [map]}` - List of maps containing :priority and :server keys
    * `{:error, :lookup_failed}` - When lookup fails

  ## Example
      ```
      iex> DomainTwistex.DNS.get_mx_records("example.com")
      {:ok, [%{priority: 10, server: "mail.example.com"}]}
      ```
  """
  def get_mx_records(domain) do
    try do
      case :inet_res.lookup(String.to_charlist(domain), :in, :mx) do
        [] ->
          {:ok, []}

        mx_records when is_list(mx_records) ->
          records =
            Enum.map(mx_records, fn {priority, server} ->
              %{
                priority: priority,
                server: server |> List.to_string()
              }
            end)

          {:ok, records}

        _ ->
          {:error, :invalid_response}
      end
    rescue
      _ -> {:error, :lookup_failed}
    end
  end

  @doc """
  Retrieves TXT records for a domain.

  ## Parameters
    * domain - String representing the domain to query

  ## Returns
    * `{:ok, [string]}` - List of TXT record strings
    * `{:error, string}` - Error message if lookup fails

  ## Example
      ```
      iex> DomainTwistex.DNS.get_txt_records("example.com")
      {:ok, ["v=spf1 -all"]}
      ```
  """
  def get_txt_records(domain) do
    case :inet_res.resolve(String.to_charlist(domain), :in, :txt) do
      {:ok, dns_response} ->
        records =
          dns_response
          |> elem(3)
          |> Enum.map(&(elem(&1, 6) |> List.to_string()))

        {:ok, records}

      {:error, reason} ->
        {:error, "Failed to retrieve TXT records: #{inspect(reason)}"}
    end
  end

  # Private Functions

  @doc false
  defp lookup_a_records(domain) do
    case :inet_res.lookup(String.to_charlist(domain), :in, :a) do
      [] ->
        {:error, :no_records}

      ips when is_list(ips) ->
        {:ok, Enum.map(ips, &(:inet.ntoa(&1) |> to_string()))}

      _ ->
        {:error, :invalid_response}
    end
  end
end
