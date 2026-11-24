defmodule DomainTwistex.PermutateTest do
  use ExUnit.Case, async: true

  alias DomainTwistex.Permutate

  describe "generate_permutations/1" do
    test "generates permutations for a simple domain" do
      results = Permutate.generate_permutations("test.com")

      assert is_list(results)
      assert length(results) > 0

      kinds = results |> Enum.map(& &1.kind) |> MapSet.new()
      assert MapSet.member?(kinds, "Addition")
      assert MapSet.member?(kinds, "Omission")
      assert MapSet.member?(kinds, "Tld")
      assert MapSet.member?(kinds, "Homoglyph")
    end

    test "returns maps with fqdn, tld, and kind keys" do
      [first | _] = Permutate.generate_permutations("example.com")

      assert Map.has_key?(first, :fqdn)
      assert Map.has_key?(first, :tld)
      assert Map.has_key?(first, :kind)
    end

    test "never includes the original domain" do
      fqdns = "snowfly.com" |> Permutate.generate_permutations() |> Enum.map(& &1.fqdn)

      refute "snowfly.com" in fqdns
      assert "snowfly.net" in fqdns
    end

    test "does not produce invalid FQDNs" do
      results = Permutate.generate_permutations("test.com")

      for %{fqdn: fqdn} <- results, label <- String.split(fqdn, ".") do
        refute label == ""
        refute String.starts_with?(label, "-")
        refute String.ends_with?(label, "-")
        assert byte_size(label) <= 63

        if String.slice(label, 2, 2) == "--",
          do: assert(String.starts_with?(label, "xn--"))
      end
    end

    test "all fqdns are ASCII and Unicode permutations carry a :unicode key" do
      results = Permutate.generate_permutations("example.com", kinds: [:homoglyph])

      assert Enum.all?(results, &DomainTwistex.IDNA.ascii?(&1.fqdn))

      unicode = Enum.filter(results, &Map.has_key?(&1, :unicode))
      assert unicode != []

      for perm <- unicode do
        assert String.starts_with?(perm.fqdn, "xn--")
        refute DomainTwistex.IDNA.ascii?(perm.unicode)
      end
    end

    test "vowel_shuffle is opt-in" do
      default = Permutate.generate_permutations("google.com")
      with_shuffle = Permutate.generate_permutations("google.com", vowel_shuffle: true)

      refute Enum.any?(default, &(&1.kind == "VowelShuffle"))
      assert length(with_shuffle) > length(default)
    end

    test "vowel_shuffle is capped for vowel-heavy names" do
      shuffles =
        "automobile.com"
        |> Permutate.generate_permutations(kinds: [:vowel_shuffle])

      assert length(shuffles) <= 625
    end

    test "supports opts to enable faux_tld" do
      without_faux = Permutate.generate_permutations("test.com", faux_tld: false)
      with_faux = Permutate.generate_permutations("test.com", faux_tld: true)

      assert length(with_faux) > length(without_faux)
    end

    test "deduplicates by fqdn" do
      fqdns = "test.com" |> Permutate.generate_permutations() |> Enum.map(& &1.fqdn)

      assert fqdns == Enum.uniq(fqdns)
    end

    test "tlds option selects the TLD list" do
      common = Permutate.generate_permutations("test.com", kinds: [:tld])
      all = Permutate.generate_permutations("test.com", kinds: [:tld], tlds: :all)
      custom = Permutate.generate_permutations("test.com", kinds: [:tld], tlds: ["net", "org"])

      assert length(all) > length(common) * 10
      assert Enum.map(custom, & &1.fqdn) == ["test.net", "test.org"]
    end

    test "kinds accepts atoms and strings" do
      by_atom = Permutate.generate_permutations("test.com", kinds: [:omission])
      by_string = Permutate.generate_permutations("test.com", kinds: ["Omission"])

      assert by_atom == by_string
      assert Enum.all?(by_atom, &(&1.kind == "Omission"))
    end

    test "handles one- and two-character labels without crashing" do
      for domain <- ["a.com", "ab.com", "x.co.uk"] do
        assert [_ | _] = Permutate.generate_permutations(domain)
      end
    end

    test "normalizes case, URLs, and subdomains" do
      expected = Permutate.generate_permutations("example.com")

      assert Permutate.generate_permutations("Example.COM") == expected
      assert Permutate.generate_permutations("https://www.example.com/login") == expected
    end

    test "uses the public suffix for multi-part TLDs" do
      results = Permutate.generate_permutations("mail.example.co.uk", kinds: [:omission])

      assert "exmple.co.uk" in Enum.map(results, & &1.fqdn)
      assert Enum.all?(results, &(&1.tld == "co.uk"))
    end

    test "mapped replaces every occurrence, not just the first" do
      fqdns =
        "google.com" |> Permutate.generate_permutations(kinds: [:mapped]) |> Enum.map(& &1.fqdn)

      assert "g0ogle.com" in fqdns
      assert "go0gle.com" in fqdns
    end

    test "priv/keywords.txt is sorted, deduplicated, lowercase, and covers s-z and priority keywords" do
      lines =
        :code.priv_dir(:domaintwistex)
        |> Path.join("keywords.txt")
        |> File.read!()
        |> String.split("\n", trim: true)

      assert lines == Enum.uniq(lines)
      assert lines == Enum.sort(lines)
      assert Enum.all?(lines, &(&1 == String.downcase(&1)))
      assert Enum.any?(lines, &String.starts_with?(&1, "t"))
      assert Enum.any?(lines, &String.starts_with?(&1, "w"))
      assert Enum.any?(lines, &String.starts_with?(&1, "z"))
      assert MapSet.subset?(MapSet.new(Permutate.priority_keywords()), MapSet.new(lines))
    end

    test "default run generates recruiting, ShinyHunters SSO, and legal lures" do
      fqdns =
        "brand.com"
        |> Permutate.generate_permutations()
        |> MapSet.new(& &1.fqdn)

      for expected <- [
            "brandhires.com",
            "brandhiring.com",
            "brandcareers.com",
            "brandjobs.com",
            "brandrecruiting.com",
            "lifeatbrand.com",
            "brandinterviews.com",
            "brand-webinar.com",
            "brandsso.com",
            "brand-okta.com",
            "ticket-brand.com",
            "brandpasskey.com",
            "brandsupport.com",
            "brandportal.com",
            "brandauth.com",
            "legal-brand.com",
            "legaldept-brand.com",
            "brand-legal.com",
            "brand.legal",
            "brand.careers",
            "brand.claims",
            "brand.report"
          ] do
        assert MapSet.member?(fqdns, expected), "expected #{expected} in default permutations"
      end
    end

    test "supports custom :keywords and :extra_keywords options" do
      custom =
        "acme.com"
        |> Permutate.generate_permutations(
          kinds: [:keyword],
          keywords: ["alpha"],
          extra_keywords: ["Beta"]
        )
        |> Enum.map(& &1.fqdn)

      assert "acme-alpha.com" in custom
      assert "acmebeta.com" in custom
      refute "acmesso.com" in custom

      priority =
        "acme.com"
        |> Permutate.generate_permutations(kinds: [:keyword], keywords: :priority)

      legacy_priority =
        "acme.com"
        |> Permutate.generate_permutations(kinds: [:keyword], priority_keywords_only: true)

      assert priority == legacy_priority

      assert length(priority) <
               length(Permutate.generate_permutations("acme.com", kinds: [:keyword]))
    end

    test "aliases run through Keyword, Compound, and Hosted without typo noise" do
      perms =
        Permutate.generate_permutations("vertex.com", aliases: ["VRTX", "kmx.com"], hosted: true)

      fqdns = MapSet.new(perms, & &1.fqdn)

      assert MapSet.member?(fqdns, "legal-vrtx.com")
      assert MapSet.member?(fqdns, "vrtxhires.com")
      assert MapSet.member?(fqdns, "kmxclaims.com")
      assert MapSet.member?(fqdns, "myvrtxsso.com")
      assert MapSet.member?(fqdns, "connect-pages-vrtx.pages.dev")
      # Short tickers must not be fed into typo/omission/addition fuzzers
      refute MapSet.member?(fqdns, "vtx.com")
      refute MapSet.member?(fqdns, "vrtxa.com")
    end

    test "keyword_tlds covers non-.com fallback and explicit cross-TLD scopes" do
      non_com_default =
        "acme.io"
        |> Permutate.generate_permutations(kinds: [:keyword])
        |> MapSet.new(& &1.fqdn)

      assert MapSet.member?(non_com_default, "acmehires.io")
      assert MapSet.member?(non_com_default, "acmehires.com")
      assert MapSet.member?(non_com_default, "acmesso.com")

      non_com_disabled =
        "acme.io"
        |> Permutate.generate_permutations(kinds: [:keyword], keyword_tlds: [])
        |> MapSet.new(& &1.fqdn)

      assert MapSet.member?(non_com_disabled, "acmehires.io")
      refute MapSet.member?(non_com_disabled, "acmehires.com")

      explicit_priority =
        "acme.com"
        |> Permutate.generate_permutations(
          kinds: [:keyword],
          keyword_tlds: ["support", ".claims", "legal"],
          keyword_tlds_scope: :priority
        )
        |> MapSet.new(& &1.fqdn)

      assert MapSet.member?(explicit_priority, "ticket-acme.support")
      assert MapSet.member?(explicit_priority, "acme-claims.claims")
      assert MapSet.member?(explicit_priority, "legal-acme.legal")
    end

    test "compound generates two-sided wrappers and respects compound: false" do
      compounds =
        "disney.com"
        |> Permutate.generate_permutations(kinds: [:compound])
        |> MapSet.new(& &1.fqdn)

      assert MapSet.member?(compounds, "mydisneysso.com")
      assert MapSet.member?(compounds, "my-disney-sso.com")
      assert MapSet.member?(compounds, "mydisneyinternal.com")
      assert MapSet.member?(compounds, "ondisneyzendesk.com")
      assert MapSet.member?(compounds, "disney-my-salesforce.com")
      assert MapSet.member?(compounds, "oktalogin-disney.com")
      assert MapSet.member?(compounds, "lifeatdisneycareers.com")

      without_compound = Permutate.generate_permutations("disney.com", compound: false)
      refute Enum.any?(without_compound, &(&1.kind == "Compound"))
    end

    test "homoglyph includes Latin hooks and Cyrillic lookalikes, and respects cyrillic: false" do
      okta = Permutate.generate_permutations("okta.com", kinds: [:homoglyph])
      okta_unicode = MapSet.new(okta, &Map.get(&1, :unicode, &1.fqdn))
      assert MapSet.member?(okta_unicode, "oƙta.com")

      apple = Permutate.generate_permutations("apple.com", kinds: [:homoglyph])
      apple_unicode = MapSet.new(apple, &Map.get(&1, :unicode, &1.fqdn))
      assert MapSet.member?(apple_unicode, "аррӏө.com")

      latin_only =
        Permutate.generate_permutations("apple.com", kinds: [:homoglyph], cyrillic: false)

      refute Enum.any?(latin_only, fn p ->
               u = Map.get(p, :unicode, p.fqdn)
               Enum.any?(String.to_charlist(u), &(&1 in 0x0400..0x052F))
             end)

      # Long Cyrillic-mappable labels remain bounded
      long_label = String.duplicate("e", 30) <> ".com"
      assert length(Permutate.generate_permutations(long_label, kinds: [:homoglyph])) < 1_000
    end

    test "hosted is opt-in and supports custom PaaS suffixes" do
      default = Permutate.generate_permutations("acme.com")
      refute Enum.any?(default, &(&1.kind == "Hosted"))

      hosted =
        Permutate.generate_permutations("acme.com",
          hosted: true,
          hosted_suffixes: ["pages.dev", ".workers.dev"]
        )
        |> Enum.filter(&(&1.kind == "Hosted"))

      fqdns = MapSet.new(hosted, & &1.fqdn)
      assert MapSet.member?(fqdns, "acme.pages.dev")
      assert MapSet.member?(fqdns, "connect-pages-acme.pages.dev")
      assert MapSet.member?(fqdns, "acme-hires.pages.dev")
      assert MapSet.member?(fqdns, "connect-pages-acme.workers.dev")

      assert Enum.any?(
               hosted,
               &(&1.fqdn == "connect-pages-acme.pages.dev" and &1.tld == "pages.dev")
             )
    end

    test "rejects malformed permutation options" do
      assert_raise ArgumentError, fn ->
        Permutate.generate_permutations("test.com", keywords: :bogus)
      end

      assert_raise ArgumentError, fn ->
        Permutate.generate_permutations("test.com", keyword_tlds_scope: :bogus)
      end
    end
  end
end
