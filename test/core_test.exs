defmodule DomainTwistex.CoreTest do
  use ExUnit.Case, async: true

  alias DomainTwistex.{Domain, HTTP, IDNA, SPF, Utils}

  doctest DomainTwistex.IDNA
  doctest DomainTwistex.Domain

  describe "IDNA" do
    test "encodes RFC 3492 sample labels" do
      assert IDNA.to_ascii("bücher.de") == "xn--bcher-kva.de"
      assert IDNA.to_ascii("münchen.de") == "xn--mnchen-3ya.de"
      assert IDNA.to_ascii("例え.jp") == "xn--r8jz45g.jp"
    end

    test "leaves ASCII untouched" do
      assert IDNA.to_ascii("xn--bcher-kva.de") == "xn--bcher-kva.de"
    end
  end

  describe "Domain" do
    test "splits using the public suffix list" do
      assert Domain.split("example.com") == {"example", "com"}
      assert Domain.split("a.b.example.co.uk") == {"example", "co.uk"}
      assert Domain.registrable("spf.protection.outlook.com") == "outlook.com"
    end

    test "normalizes messy input" do
      assert Domain.normalize("  user@Example.com.  ") == "example.com"
      assert Domain.normalize("http://example.com:8080") == "example.com"
    end
  end

  describe "IP classification" do
    test "flags private, loopback, and special ranges" do
      assert Utils.ip_flag({127, 0, 0, 2}) == :localhost
      assert Utils.ip_flag({172, 20, 1, 1}) == :private_172
      assert Utils.ip_flag({100, 64, 0, 1}) == :cgnat
      assert Utils.ip_flag({169, 254, 1, 1}) == :link_local
      assert Utils.ip_flag({0, 0, 0, 0, 0, 0, 0, 1}) == :localhost
      assert Utils.ip_flag({0xFD00, 0, 0, 0, 0, 0, 0, 1}) == :ipv6_ula
      assert Utils.ip_flag({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001}) == :private_10
    end

    test "public addresses are unflagged" do
      assert Utils.ip_flag({8, 8, 8, 8}) == nil
      assert Utils.ip_flag({172, 32, 0, 1}) == nil
      assert Utils.ip_flag({0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}) == nil
    end

    test "classify_ips splits public and internal" do
      result = Utils.classify_ips([{8, 8, 8, 8}, {10, 0, 0, 1}])

      assert result.public_ips == ["8.8.8.8"]
      assert result.internal_ips == ["10.0.0.1"]
      assert result.flags == [:private_10]
    end
  end

  describe "fuzzy scores" do
    test "compares names left of the public suffix" do
      scores = Utils.calculate_fuzzy_scores("example.com", "exmaple.com")

      assert scores.levenshtein == 2
      refute scores.tld_changed
    end

    test "TLD swaps are identical names with tld_changed" do
      scores = Utils.calculate_fuzzy_scores("example.com", "example.net")

      assert scores.levenshtein == 0
      assert scores.tld_changed
    end

    test "subdomain permutations compare the full stem" do
      assert Utils.calculate_fuzzy_scores("example.com", "ex.ample.com").levenshtein == 1
    end
  end

  describe "SPF" do
    test "parses qualifiers, modifiers, and bare mechanisms" do
      spf =
        SPF.parse_spf_record(
          "v=spf1  a mx -include:_spf.google.com ip4:1.2.3.0/24 redirect=_spf.example.com ~all"
        )

      assert %{type: :include, qualifier: :fail, value: "_spf.google.com"} in spf.mechanisms
      assert %{type: :a, qualifier: :pass, value: nil} in spf.mechanisms
      assert %{type: :ip4, qualifier: :pass, value: "1.2.3.0/24"} in spf.mechanisms
      assert spf.redirect == "_spf.example.com"
      assert spf.all_mechanism == "~all"
      # a + mx + include + redirect
      assert spf.lookup_count == 4
      refute Enum.any?(spf.mechanisms, &(&1.type == :unknown))
    end

    test "is case-insensitive and warns on risky records" do
      spf = SPF.parse_txt_records({:ok, ["V=SPF1 +all"]})

      assert spf.all_mechanism == "+all"
      assert "+all permits any sender" in spf.warnings
    end

    test "warns about multiple SPF records" do
      spf = SPF.parse_txt_records({:ok, ["v=spf1 -all", "v=spf1 ~all"]})

      assert Enum.any?(spf.warnings, &String.starts_with?(&1, "multiple SPF records"))
    end

    test "returns an error without an SPF record" do
      assert {:error, _} = SPF.parse_txt_records({:ok, ["google-site-verification=abc"]})
    end

    test "results are JSON-encodable" do
      spf = SPF.parse_spf_record("v=spf1 include:sendgrid.net -all")

      assert {:ok, _} = Jason.encode(spf)
    end
  end

  describe "HTTP.parse_response/1" do
    test "extracts status, headers, location, and title" do
      raw =
        "HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nLocation: https://example.com/\r\n\r\n" <>
          "<html><head><title>\n  Sign in  </title></head></html>"

      response = HTTP.parse_response(raw)

      assert response.status_code == 301
      assert response.server == "nginx"
      assert response.location == "https://example.com/"
      assert response.title == "Sign in"
    end

    test "rejects non-HTTP responses" do
      assert %{status: :error} = HTTP.parse_response("SSH-2.0-OpenSSH_9.0\r\n")
    end
  end

  describe "results" do
    test "are JSON-encodable without post-processing" do
      perm = %{fqdn: "exmaple.com", tld: "com", kind: "Transposition"}
      probe = %{ips: [{93, 184, 216, 34}, {10, 0, 0, 1}], cname: nil}
      result = Utils.minimal_result(perm, probe, %{domain: "example.com"})

      assert result.spf_records == nil
      assert {:ok, _} = Jason.encode(result)
    end
  end

  describe "probe accounting" do
    alias DomainTwistex.Twist

    test "counts DNS timeouts as both errors and timeouts" do
      counters = Twist.count_skip(%{}, {:dns_error, :timeout})

      assert counters.dns_error == 1
      assert counters.timeout == 1
    end

    test "counts other DNS failures without calling them timeouts" do
      counters = Twist.count_skip(%{}, {:dns_error, :servfail})

      assert counters == %{dns_error: 1}
    end

    test "caps in-flight probes at 40 per resolver" do
      assert Twist.dns_probe_concurrency(dns_concurrency: 200, nameservers: nil) == 40
      assert Twist.dns_probe_concurrency(dns_concurrency: 200, nameservers: ["1.1.1.1"]) == 40

      assert Twist.dns_probe_concurrency(
               dns_concurrency: 200,
               nameservers: DomainTwistex.DNS.public_nameservers()
             ) == 200

      assert Twist.dns_probe_concurrency(dns_concurrency: 10, nameservers: nil) == 10
    end
  end

  describe "option validation" do
    test "rejects unknown options" do
      assert_raise ArgumentError, fn -> DomainTwistex.analyze("example.com", bogus: true) end
    end

    test "rejects malformed nameservers" do
      assert_raise ArgumentError, fn ->
        DomainTwistex.analyze("example.com", nameservers: ["not-an-ip"])
      end
    end

    test "parses nameserver specs" do
      assert DomainTwistex.DNS.parse_nameservers([
               "1.1.1.1",
               "8.8.8.8:5353",
               "[2606:4700::1111]:53"
             ]) ==
               [
                 {{1, 1, 1, 1}, 53},
                 {{8, 8, 8, 8}, 5353},
                 {{0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}, 53}
               ]
    end
  end
end
