defmodule DomainTwistex.HTTP do
  @moduledoc """
  Lightweight HTTP and HTTPS probing for suspicious domains.

  Connects directly to an already-resolved IP (so results match the DNS data
  and no second resolver is involved), sends `GET /`, and captures the status,
  `Server` and `Location` headers, page title, and — for HTTPS — the TLS
  certificate's issuer, names, and validity window.

  Certificates are inspected without verification on purpose: phishing sites
  frequently serve invalid or mismatched certificates, and those are exactly
  the ones worth recording.
  """

  @max_response_bytes 64 * 1024
  @default_timeout 5_000
  @user_agent "Mozilla/5.0 (compatible; DomainTwistex)"

  @type response :: %{
          optional(:status_code) => non_neg_integer(),
          optional(:server) => String.t() | nil,
          optional(:location) => String.t() | nil,
          optional(:title) => String.t() | nil,
          optional(:headers) => map(),
          optional(:status) => :error,
          optional(:reason) => String.t()
        }

  @doc """
  Probes HTTP (port 80) and HTTPS (port 443) concurrently.

  ## Parameters

    * `host` - Hostname for the `Host` header and TLS SNI
    * `ip` - IP tuple to connect to
    * `opts` - `:http_timeout` in milliseconds (default: 5_000)

  ## Returns

      %{http: response, https: response, tls: tls_info | nil}

  """
  @spec probe(String.t(), :inet.ip_address(), keyword()) :: %{
          http: response(),
          https: response(),
          tls: map() | nil
        }
  def probe(host, ip, opts \\ []) do
    timeout = Keyword.get(opts, :http_timeout, @default_timeout)

    http = Task.async(fn -> get_http(host, ip, timeout) end)
    https = Task.async(fn -> get_https(host, ip, timeout) end)

    [http_result, https_result] =
      [http, https]
      |> Task.yield_many(timeout * 2 + 500)
      |> Enum.map(fn
        {_task, {:ok, result}} ->
          result

        {task, _} ->
          Task.shutdown(task, :brutal_kill)
          {error("timeout"), nil}
      end)

    {http_response, _} = http_result
    {https_response, tls} = https_result

    %{http: http_response, https: https_response, tls: tls}
  end

  # =============================================================================
  # Transports
  # =============================================================================

  defp get_http(host, ip, timeout) do
    case :gen_tcp.connect(ip, 80, [:binary, family(ip), active: false, packet: :raw], timeout) do
      {:ok, socket} ->
        response = request(:gen_tcp, socket, host, timeout)
        :gen_tcp.close(socket)
        {response, nil}

      {:error, reason} ->
        {error("connect failed: #{inspect(reason)}"), nil}
    end
  end

  defp get_https(host, ip, timeout) do
    ssl_opts = [
      :binary,
      family(ip),
      active: false,
      packet: :raw,
      verify: :verify_none,
      server_name_indication: String.to_charlist(host),
      versions: [:"tlsv1.3", :"tlsv1.2"]
    ]

    case :ssl.connect(ip, 443, ssl_opts, timeout) do
      {:ok, socket} ->
        tls =
          case :ssl.peercert(socket) do
            {:ok, der} -> safe(fn -> decode_cert(der) end)
            _ -> nil
          end

        response = request(:ssl, socket, host, timeout)
        :ssl.close(socket)
        {response, tls}

      {:error, reason} ->
        {error("tls connect failed: #{inspect(reason)}"), nil}
    end
  end

  defp family(ip) when tuple_size(ip) == 8, do: :inet6
  defp family(_ip), do: :inet

  defp request(mod, socket, host, timeout) do
    req =
      "GET / HTTP/1.1\r\nHost: #{host}\r\nUser-Agent: #{@user_agent}\r\n" <>
        "Accept: text/html,*/*\r\nConnection: close\r\n\r\n"

    deadline = System.monotonic_time(:millisecond) + timeout

    with :ok <- mod.send(socket, req),
         {:ok, raw} <- recv(mod, socket, <<>>, deadline) do
      parse_response(raw)
    else
      {:error, reason} -> error("request failed: #{inspect(reason)}")
    end
  end

  defp recv(_mod, _socket, acc, _deadline) when byte_size(acc) >= @max_response_bytes,
    do: {:ok, acc}

  defp recv(mod, socket, acc, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      if acc == <<>>, do: {:error, :timeout}, else: {:ok, acc}
    else
      case mod.recv(socket, 0, remaining) do
        {:ok, data} -> recv(mod, socket, acc <> data, deadline)
        {:error, _} when acc != <<>> -> {:ok, acc}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # =============================================================================
  # Response parsing
  # =============================================================================

  @doc false
  @spec parse_response(binary()) :: response()
  def parse_response(raw) do
    {head, body} =
      case :binary.split(raw, "\r\n\r\n") do
        [head, body] -> {head, body}
        [head] -> {head, ""}
      end

    [status_line | header_lines] = head |> String.replace_invalid() |> String.split("\r\n")

    case Regex.run(~r|^HTTP/\d(?:\.\d)?\s+(\d{3})|, status_line) do
      [_, code] ->
        headers =
          Map.new(
            for line <- header_lines,
                [key, value] <- [String.split(line, ":", parts: 2)],
                do: {String.downcase(String.trim(key)), String.trim(value)}
          )

        %{
          status_code: String.to_integer(code),
          server: headers["server"],
          location: headers["location"],
          title: extract_title(body),
          headers: headers
        }

      _ ->
        error("invalid HTTP response")
    end
  end

  defp extract_title(body) do
    body = String.replace_invalid(body)

    case Regex.run(~r{<title[^>]*>(.*?)</title>}is, body) do
      [_, title] ->
        title
        |> String.replace(~r/\s+/, " ")
        |> String.trim()
        |> String.slice(0, 200)
        |> case do
          "" -> nil
          t -> t
        end

      _ ->
        nil
    end
  end

  # =============================================================================
  # Certificate decoding
  # =============================================================================

  @oid_cn {2, 5, 4, 3}
  @oid_org {2, 5, 4, 10}
  @oid_san {2, 5, 29, 17}

  defp decode_cert(der) do
    {:OTPCertificate, tbs, _alg, _sig} = :public_key.pkix_decode_cert(der, :otp)

    issuer = elem(tbs, 4)
    {:Validity, not_before, not_after} = elem(tbs, 5)
    subject = elem(tbs, 6)
    extensions = elem(tbs, 10)

    not_before = cert_time(not_before)
    not_after = cert_time(not_after)

    %{
      issuer: rdn(issuer, @oid_org) || rdn(issuer, @oid_cn),
      issuer_cn: rdn(issuer, @oid_cn),
      subject_cn: rdn(subject, @oid_cn),
      sans: sans(extensions),
      not_before: not_before && DateTime.to_iso8601(not_before),
      not_after: not_after && DateTime.to_iso8601(not_after),
      age_days: not_before && DateTime.diff(DateTime.utc_now(), not_before, :day),
      self_signed: issuer == subject
    }
  end

  defp rdn({:rdnSequence, sets}, oid) do
    Enum.find_value(List.flatten(sets), fn
      {:AttributeTypeAndValue, ^oid, value} -> attr_string(value)
      _ -> nil
    end)
  end

  defp rdn(_, _), do: nil

  defp attr_string({_type, value}) when is_binary(value) or is_list(value),
    do: to_string(value)

  defp attr_string(value) when is_binary(value) or is_list(value), do: to_string(value)
  defp attr_string(_), do: nil

  defp sans(extensions) when is_list(extensions) do
    Enum.find_value(extensions, [], fn
      {:Extension, @oid_san, _critical, names} when is_list(names) ->
        for {:dNSName, name} <- names, do: to_string(name)

      _ ->
        nil
    end)
  end

  defp sans(_), do: []

  defp cert_time({:utcTime, time}) do
    [yy | rest] = time |> to_string() |> chunks()
    year = if yy >= 50, do: 1900 + yy, else: 2000 + yy
    build_datetime([year | rest])
  end

  defp cert_time({:generalTime, time}) do
    <<year::binary-4, rest::binary>> = to_string(time)
    build_datetime([String.to_integer(year) | chunks(rest)])
  end

  defp cert_time(_), do: nil

  defp chunks(digits) do
    for <<pair::binary-2 <- String.trim_trailing(digits, "Z")>>, do: String.to_integer(pair)
  end

  defp build_datetime([year, month, day, hour, minute, second | _]) do
    case NaiveDateTime.new(year, month, day, hour, minute, second) do
      {:ok, naive} -> DateTime.from_naive!(naive, "Etc/UTC")
      _ -> nil
    end
  end

  defp build_datetime(_), do: nil

  defp error(reason), do: %{status: :error, reason: reason}

  defp safe(fun) do
    fun.()
  rescue
    _ -> nil
  end
end
