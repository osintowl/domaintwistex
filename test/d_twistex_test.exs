defmodule DomainTwistex.PermutateTest do
  use ExUnit.Case

  describe "generate_permutations/1" do
    test "generates permutations for a simple domain" do
      results = DomainTwistex.Permutate.generate_permutations("test.com")

      assert is_list(results)
      assert length(results) > 0

      kinds = results |> Enum.map(& &1.kind) |> MapSet.new()
      assert MapSet.member?(kinds, "Addition")
      assert MapSet.member?(kinds, "Omission")
      assert MapSet.member?(kinds, "Tld")
      assert MapSet.member?(kinds, "Homoglyph")
    end

    test "returns maps with fqdn, tld, and kind keys" do
      [first | _] = DomainTwistex.Permutate.generate_permutations("example.com")

      assert Map.has_key?(first, :fqdn)
      assert Map.has_key?(first, :tld)
      assert Map.has_key?(first, :kind)
    end

    test "Tld permutations can reproduce the original domain" do
      results = DomainTwistex.Permutate.generate_permutations("snowfly.com")

      # The Tld permutation type includes all known TLDs, which includes .com
      tld_results = Enum.filter(results, &(&1.kind == "Tld"))
      tld_domains = Enum.map(tld_results, & &1.fqdn)

      assert "snowfly.com" in tld_domains
    end

    test "does not produce invalid FQDNs" do
      results = DomainTwistex.Permutate.generate_permutations("test.com")

      for %{fqdn: fqdn} <- results do
        refute fqdn == ""
        refute String.contains?(fqdn, "..")
        refute String.starts_with?(fqdn, ".")
        refute String.ends_with?(fqdn, ".")
        refute String.contains?(fqdn, "--")
      end
    end

    test "supports opts to disable vowel_shuffle" do
      with_shuffle = DomainTwistex.Permutate.generate_permutations("google.com", vowel_shuffle: true)
      without_shuffle = DomainTwistex.Permutate.generate_permutations("google.com", vowel_shuffle: false)

      assert length(with_shuffle) > length(without_shuffle)
    end

    test "supports opts to enable faux_tld" do
      without_faux = DomainTwistex.Permutate.generate_permutations("test.com", faux_tld: false)
      with_faux = DomainTwistex.Permutate.generate_permutations("test.com", faux_tld: true)

      assert length(with_faux) > length(without_faux)
    end

    test "deduplicates by fqdn" do
      results = DomainTwistex.Permutate.generate_permutations("test.com")
      fqdns = Enum.map(results, & &1.fqdn)

      assert fqdns == Enum.uniq(fqdns)
    end
  end
end