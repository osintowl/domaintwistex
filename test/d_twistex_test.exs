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
  end
end
