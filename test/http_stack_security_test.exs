defmodule DomainTwistex.HttpStackSecurityTest do
  use ExUnit.Case, async: false

  @rdap_cache_key :domaintwistex_rdap_bootstrap

  setup do
    DomainTwistex.Whois.clear_cache()
    on_exit(fn -> DomainTwistex.Whois.clear_cache() end)
    :ok
  end

  describe "RDAP client" do
    test "decodes an uncompressed JSON document" do
      body =
        Jason.encode!(%{
          "entities" => [
            %{
              "roles" => ["registrar"],
              "vcardArray" => ["vcard", [["fn", %{}, "text", "Example Registrar"]]]
            }
          ],
          "events" => [%{"eventAction" => "registration", "eventDate" => "2020-01-02T00:00:00Z"}],
          "status" => ["active"],
          "nameservers" => [%{"ldhName" => "ns1.example.test"}]
        })

      serve_whois("example.test", "application/json", body)

      assert {:ok, result} = DomainTwistex.Whois.lookup("example.test")
      assert result.source == "rdap"
      assert result.registrar == "Example Registrar"
      assert result.creation_date == "2020-01-02T00:00:00Z"
      assert result.status == ["active"]
      assert result.nameservers == ["ns1.example.test"]
    end

    test "treats an RDAP 404 as not registered" do
      serve_whois("missing.test", "application/json", ~s({"error":"not found"}), 404)

      assert {:error, "Domain not found in RDAP"} = DomainTwistex.Whois.lookup("missing.test")
    end

    test "does not treat a non-JSON success body as a registration document" do
      serve_whois("text.test", "text/plain", "registered: yes")

      # A non-JSON body is not a registration document. RDAP errors other than
      # 404 fall through to WHOIS, and the .test TLD has no WHOIS server.
      assert {:error, "No WHOIS server for TLD: test"} =
               DomainTwistex.Whois.lookup("text.test")
    end

    test "does not inflate a gzip-encoded RDAP body into a parsed document" do
      json = Jason.encode!(%{"entities" => [], "status" => ["active"]})
      serve_whois("gzip.test", "application/json", :zlib.gzip(json), 200, "gzip")

      # Inflating this body would produce a registration document. Leaving it
      # packed makes RDAP fail closed and fall through to WHOIS.
      assert {:error, "No WHOIS server for TLD: test"} =
               DomainTwistex.Whois.lookup("gzip.test")
    end
  end

  describe "response body decoding" do
    test "leaves an application/zip body packed" do
      {:ok, {_name, zip}} = :zip.create(~c"archive.zip", [{~c"file.txt", "hi"}], [:memory])
      url = serve("application/zip", zip)

      assert {:ok, response} = Req.get(url, retry: false, receive_timeout: 2_000)
      assert response.status == 200
      assert response.body == zip
    end
  end

  describe "HTTP/1 framing" do
    test "reads a chunked body and a chunk extension" do
      responses =
        mint_exchange(
          "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )

      assert response_body(responses) == "hello"

      extended =
        mint_exchange(
          "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n"
        )

      assert response_body(extended) == "hello"
    end

    test "rejects a chunk-size line with a non-extension tail" do
      responses =
        mint_exchange(
          "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5ZZZZZ\r\nhello\r\n0\r\n\r\n"
        )

      refute response_body(responses) == "hello"
      assert framing_error?(responses)
    end

    test "rejects a signed content-length" do
      responses =
        mint_exchange("HTTP/1.1 200 OK\r\ncontent-length: +5\r\n\r\nhello")

      refute response_body(responses) == "hello"
      assert framing_error?(responses)
    end

    test "reads a digit-only content-length" do
      responses = mint_exchange("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")

      assert response_body(responses) == "hello"
      refute framing_error?(responses)
    end
  end

  describe "HPACK integer limits" do
    test "accepts a small dynamic table size update" do
      # Prefix of 5 bits, value 32: 0x3F then a single terminating octet.
      assert {:ok, [], _table} = HPAX.decode(<<0x3F, 0x01>>, HPAX.new(4096))
    end

    test "rejects an integer with too many continuation octets" do
      # Six continuation octets, then a terminator. hpax 1.0.3 decodes the
      # oversized integer and only then rejects it as a table-size update.
      block = <<0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00>>

      assert {:error, :bad_integer_encoding} = HPAX.decode(block, HPAX.new(4096))
    end
  end

  defp serve_whois(domain, content_type, body, status \\ 200, encoding \\ nil) do
    url = serve(content_type, body, status, encoding)
    tld = domain |> String.split(".") |> List.last()
    :persistent_term.put(@rdap_cache_key, %{tld => url})
  end

  defp serve(content_type, body, status \\ 200, encoding \\ nil) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        packet: :raw,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, port} = :inet.port(listen)
    parent = self()

    spawn(fn ->
      {:ok, socket} = :gen_tcp.accept(listen)

      case :gen_tcp.recv(socket, 0, 5_000) do
        {:ok, request} ->
          send(parent, {:request, request})
          response = http_response(status, content_type, body, encoding)
          :gen_tcp.send(socket, response)

        {:error, reason} ->
          send(parent, {:request_error, reason})
      end

      :gen_tcp.close(socket)
    end)

    on_exit(fn -> :gen_tcp.close(listen) end)
    "http://127.0.0.1:#{port}/"
  end

  defp http_response(status, content_type, body, encoding) do
    reason =
      case status do
        200 -> "OK"
        404 -> "Not Found"
        _ -> "Status"
      end

    encoding_header = if encoding, do: "content-encoding: #{encoding}\r\n", else: ""

    "HTTP/1.1 #{status} #{reason}\r\n" <>
      "content-type: #{content_type}\r\n" <>
      encoding_header <>
      "content-length: #{byte_size(body)}\r\n" <>
      "connection: close\r\n\r\n" <>
      body
  end

  defp mint_exchange(raw_response) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        packet: :raw,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, port} = :inet.port(listen)

    spawn(fn ->
      {:ok, socket} = :gen_tcp.accept(listen)
      _ = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.send(socket, raw_response)
      :gen_tcp.close(socket)
    end)

    result =
      with {:ok, conn} <-
             Mint.HTTP.connect(:http, "127.0.0.1", port,
               mode: :passive,
               protocols: [:http1]
             ),
           {:ok, conn, _ref} <- Mint.HTTP.request(conn, "GET", "/", [], nil) do
        drain(conn, [])
      end

    :gen_tcp.close(listen)
    result
  end

  defp drain(conn, acc) do
    case Mint.HTTP.recv(conn, 0, 2_000) do
      {:ok, conn, responses} ->
        acc = acc ++ responses

        if done?(responses) or framing_error?(responses) do
          _ = Mint.HTTP.close(conn)
          acc
        else
          drain(conn, acc)
        end

      {:error, conn, reason, responses} ->
        _ = Mint.HTTP.close(conn)
        acc ++ responses ++ [{:error, nil, reason}]

      {:error, reason} ->
        acc ++ [{:error, nil, reason}]
    end
  end

  defp done?(responses) do
    Enum.any?(responses, &match?({:done, _}, &1))
  end

  defp response_body(responses) when is_list(responses) do
    for {:data, _ref, data} <- responses, into: "", do: data
  end

  defp response_body(_responses), do: ""

  defp framing_error?(responses) when is_list(responses) do
    Enum.any?(responses, &match?({:error, _, _}, &1))
  end

  defp framing_error?(_responses), do: false
end
