defmodule DomainTwistex.Permutate do
  @moduledoc """
  Pure Elixir domain permutation generator.

  Generates domain permutations using 18 different algorithms to detect
  potential typosquatting, homograph attacks, and other domain abuse patterns.

  Input is normalized (lowercased, URL parts stripped) and reduced to its
  registrable domain using the public suffix list, so `https://mail.example.co.uk/`
  is permuted as `example.co.uk`. The original domain is never included in
  the output.

  Every permutation's `:fqdn` is in ASCII form and safe to resolve. Permutations
  containing Unicode (e.g. homoglyphs) are punycode-encoded and also carry a
  `:unicode` key with the human-readable form.

  ## Permutation Types

    * Addition - Appending a-z to domain
    * Bitsquatting - Single bit flips in characters
    * Homoglyph - Visually similar Unicode characters
    * Hyphenation - Adding hyphens between characters
    * HyphenationTldBoundary - Hyphen at TLD boundary
    * Insertion - Keyboard-adjacent character insertions
    * Omission - Removing single characters
    * Repetition - Repeating characters
    * Replacement - Keyboard-adjacent character replacements
    * Subdomain - Adding dots to create subdomains
    * Transposition - Swapping adjacent characters
    * VowelSwap - Replacing vowels with other vowels
    * VowelShuffle - All vowel combinations (optional, limited)
    * DoubleVowelInsertion - Insert vowel between adjacent vowels
    * Keyword - Common phishing keywords
    * Tld - Different TLD variations
    * FauxTld - Fake TLD patterns (optional)
    * Mapped - Character to look-alike mappings (l->1, o->0)

  """

  alias DomainTwistex.{Domain, IDNA}

  @vowels_lower ~c"aeiou"
  @vowel_shuffle_ceiling 4
  @ascii_lower ~c"abcdefghijklmnopqrstuvwxyz"

  @kinds ~w(Addition Bitsquatting Homoglyph Hyphenation HyphenationTldBoundary Insertion
            Omission Repetition Replacement Subdomain Transposition VowelSwap VowelShuffle
            DoubleVowelInsertion Keyword Tld FauxTld Mapped)

  @homoglyphs %{
    ?a => ~c"àáâãäåɑạǎăȧą",
    ?b => ~c"dʙɓḃḅḇƅ",
    ?c => ~c"eƈċćçčĉo",
    ?d => ~c"bɗđďɖḑḋḍḏḓ",
    ?e => ~c"céèêëēĕěėẹęȩɇḛ",
    ?f => ~c"ƒḟ",
    ?g => ~c"qɢɡġğǵģĝǧǥ",
    ?h => ~c"ĥȟħɦḧḩⱨḣḥḫẖ",
    ?i => ~c"1líìïıɩǐĭỉịɨȋī",
    ?j => ~c"ʝɉ",
    ?k => ~c"ḳḵⱪķ",
    ?l => ~c"1iɫł",
    ?m => ~c"nṁṃᴍɱḿ",
    ?n => ~c"mrńṅṇṉñņǹňꞑ",
    ?o => ~c"0ȯọỏơóö",
    ?p => ~c"ƿƥṕṗ",
    ?q => ~c"gʠ",
    ?r => ~c"ʀɼɽŕŗřɍɾȓȑṙṛṟ",
    ?s => ~c"ʂśṣṡșŝš",
    ?t => ~c"ţŧṫṭțƫ",
    ?u => ~c"ᴜǔŭüʉùúûũūųưůűȕȗụ",
    ?v => ~c"ṿⱱᶌṽⱴ",
    ?w => ~c"ŵẁẃẅⱳẇẉẘ",
    ?y => ~c"ʏýÿŷƴȳɏỿẏỵ",
    ?z => ~c"ʐżźᴢƶẓẕⱬ"
  }

  @mapped %{
    "a" => ["4"],
    "b" => ["8", "6"],
    "d" => ["cl"],
    "e" => ["3"],
    "f" => ["ph"],
    "g" => ["9", "6"],
    "i" => ["1", "l"],
    "l" => ["1", "i"],
    "m" => ["rn", "nn"],
    "o" => ["0"],
    "q" => ["9"],
    "s" => ["5", "z"],
    "t" => ["7"],
    "u" => ["v"],
    "v" => ["u"],
    "w" => ["vv"],
    "z" => ["2", "s"],
    "0" => ["o"],
    "1" => ["i", "l"],
    "2" => ["z"],
    "3" => ["e"],
    "4" => ["a"],
    "5" => ["s"],
    "6" => ["b", "g"],
    "7" => ["t"],
    "8" => ["b"],
    "9" => ["g", "q"],
    "ck" => ["kk"],
    "oo" => ["00"]
  }

  # QWERTY keyboard layout for typo simulation
  @qwerty_adjacents %{
    ?1 => ~c"2q",
    ?2 => ~c"3wq1",
    ?3 => ~c"4ew2",
    ?4 => ~c"5re3",
    ?5 => ~c"6tr4",
    ?6 => ~c"7yt5",
    ?7 => ~c"8uy6",
    ?8 => ~c"9iu7",
    ?9 => ~c"0oi8",
    ?0 => ~c"po9",
    ?q => ~c"12wa",
    ?w => ~c"3esaq2",
    ?e => ~c"4rdsw3",
    ?r => ~c"5tfde4",
    ?t => ~c"6ygfr5",
    ?y => ~c"7uhgt6",
    ?u => ~c"8ijhy7",
    ?i => ~c"9okju8",
    ?o => ~c"0plki9",
    ?p => ~c"lo0",
    ?a => ~c"qwsz",
    ?s => ~c"edxzaw",
    ?d => ~c"rfcxse",
    ?f => ~c"tgvcdr",
    ?g => ~c"yhbvft",
    ?h => ~c"ujnbgy",
    ?j => ~c"ikmnhu",
    ?k => ~c"olmji",
    ?l => ~c"kop",
    ?z => ~c"asx",
    ?x => ~c"zsdc",
    ?c => ~c"xdfv",
    ?v => ~c"cfgb",
    ?b => ~c"vghn",
    ?n => ~c"bhjm",
    ?m => ~c"njk"
  }

  # Load TLDs and keywords at compile time
  @external_resource tlds_path = Path.join(:code.priv_dir(:domaintwistex), "tlds.txt")
  @external_resource keywords_path = Path.join(:code.priv_dir(:domaintwistex), "keywords.txt")

  @tlds tlds_path |> File.read!() |> String.split("\n", trim: true)
  @keywords keywords_path |> File.read!() |> String.split("\n", trim: true)

  # Curated default TLD set: high-traffic gTLDs/ccTLDs plus TLDs commonly
  # abused for phishing. Use `tlds: :all` for the full public suffix list.
  @common_tlds ~w(
    com net org info biz co io ai app dev xyz online site top shop store tech cloud
    live me us uk co.uk org.uk ca de fr es it nl be ch at se no dk fi pl pt ie eu
    ru ua cz sk hu ro gr tr il in cn hk tw jp kr sg my id ph th vn au com.au nz
    co.nz br com.br mx com.mx ar cl pe za ng ke eg ae sa qa mobi pro name tv cc ws
    la to fm am gg im ly vip club icu work link click space website fun network
    email support help services solutions group digital agency company global world
    one inc llc ltd media news blog page bank finance money pay security cyou buzz
    rest cfd sbs bond monster zip mov lol life today host press best run
  )
  @common_tlds Enum.filter(@common_tlds, &(&1 in @tlds))

  # High-value keywords for phishing (prioritized)
  @priority_keywords ~w(
    login signin secure account verify update confirm support help
    service alert notification mail webmail portal auth password
    billing payment invoice customer admin
  )

  @type permutation :: %{
          required(:fqdn) => String.t(),
          required(:tld) => String.t(),
          required(:kind) => String.t(),
          optional(:unicode) => String.t()
        }

  @doc """
  Returns the list of all permutation kind names.
  """
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds

  @doc """
  Returns the curated default TLD list used by the `Tld` permutation.
  """
  @spec common_tlds() :: [String.t()]
  def common_tlds, do: @common_tlds

  @doc """
  Generates all domain permutations for a given domain.

  Returns a list of maps with `:fqdn`, `:tld`, and `:kind` keys (plus
  `:unicode` for internationalized permutations).

  ## Options

    * `:tlds` - TLDs for the `Tld` permutation: `:common` (default, ~150
      curated TLDs), `:all` (full public suffix list, ~7K), or a list of strings
    * `:faux_tld` - Include FauxTld permutations (default: false)
    * `:double_vowel` - Include DoubleVowelInsertion (default: true)
    * `:vowel_shuffle` - Include VowelShuffle (default: false, up to 625 entries)
    * `:priority_keywords_only` - Only use high-value phishing keywords (default: false)
    * `:kinds` - Only generate these kinds, as strings (`"Homoglyph"`) or
      atoms (`:homoglyph`). Overrides the boolean toggles above.

  ## Examples

      iex> perms = DomainTwistex.Permutate.generate_permutations("example.com")
      iex> Enum.any?(perms, &(&1.fqdn == "exmaple.com"))
      true

  """
  @spec generate_permutations(String.t(), keyword()) :: [permutation()]
  def generate_permutations(fqdn, opts \\ []) do
    original = fqdn |> Domain.normalize() |> Domain.registrable()
    {domain, tld} = Domain.split(original)
    original_ascii = IDNA.to_ascii(original)

    opts
    |> enabled_kinds()
    |> Stream.flat_map(&generator(&1, domain, tld, opts))
    |> Stream.map(&to_ascii/1)
    |> Stream.reject(&(invalid_fqdn?(&1) or &1.fqdn == original_ascii))
    |> Stream.uniq_by(& &1.fqdn)
    |> Enum.to_list()
  end

  # =============================================================================
  # Kind selection
  # =============================================================================

  defp enabled_kinds(opts) do
    case Keyword.get(opts, :kinds) do
      nil ->
        Enum.filter(@kinds, fn
          "FauxTld" -> Keyword.get(opts, :faux_tld, false)
          "VowelShuffle" -> Keyword.get(opts, :vowel_shuffle, false)
          "DoubleVowelInsertion" -> Keyword.get(opts, :double_vowel, true)
          _ -> true
        end)

      kinds ->
        wanted = MapSet.new(kinds, &kind_name/1)
        Enum.filter(@kinds, &MapSet.member?(wanted, &1))
    end
  end

  defp kind_name(kind) when is_atom(kind), do: kind |> Atom.to_string() |> Macro.camelize()
  defp kind_name(kind) when is_binary(kind), do: kind

  defp generator("Addition", d, t, _), do: addition(d, t)
  defp generator("Bitsquatting", d, t, _), do: bitsquatting(d, t)
  defp generator("Homoglyph", d, t, _), do: homoglyph(d, t)
  defp generator("Hyphenation", d, t, _), do: hyphenation(d, t)
  defp generator("HyphenationTldBoundary", d, t, _), do: hyphenation_tld_boundary(d, t)
  defp generator("Insertion", d, t, _), do: insertion(d, t)
  defp generator("Omission", d, t, _), do: omission(d, t)
  defp generator("Repetition", d, t, _), do: repetition(d, t)
  defp generator("Replacement", d, t, _), do: replacement(d, t)
  defp generator("Subdomain", d, t, _), do: subdomain(d, t)
  defp generator("Transposition", d, t, _), do: transposition(d, t)
  defp generator("VowelSwap", d, t, _), do: vowel_swap(d, t)
  defp generator("VowelShuffle", d, t, _), do: vowel_shuffle(d, t)
  defp generator("DoubleVowelInsertion", d, t, _), do: double_vowel_insertion(d, t)
  defp generator("Mapped", d, t, _), do: mapped(d, t)
  defp generator("FauxTld", d, t, opts), do: faux_tld(d, t, tld_list(opts))
  defp generator("Tld", d, _t, opts), do: tld_swap(d, tld_list(opts))

  defp generator("Keyword", d, t, opts),
    do: keyword(d, t, Keyword.get(opts, :priority_keywords_only, false))

  defp tld_list(opts) do
    case Keyword.get(opts, :tlds, :common) do
      :common -> @common_tlds
      :all -> @tlds
      list when is_list(list) -> list
    end
  end

  # =============================================================================
  # Validation
  # =============================================================================

  defp to_ascii(%{fqdn: fqdn} = perm) do
    case IDNA.to_ascii(fqdn) do
      ^fqdn -> perm
      ascii -> Map.merge(perm, %{fqdn: ascii, unicode: fqdn})
    end
  end

  defp invalid_fqdn?(%{fqdn: fqdn}) do
    fqdn == "" or byte_size(fqdn) > 253 or
      fqdn |> String.split(".") |> Enum.any?(&invalid_label?/1)
  end

  defp invalid_label?(label) do
    label == "" or byte_size(label) > 63 or
      String.starts_with?(label, "-") or String.ends_with?(label, "-") or
      (String.slice(label, 2, 2) == "--" and not String.starts_with?(label, "xn--"))
  end

  # =============================================================================
  # Helpers
  # =============================================================================

  defp perm(chars, tld, kind) when is_list(chars), do: perm(List.to_string(chars), tld, kind)
  defp perm(name, tld, kind), do: %{fqdn: "#{name}.#{tld}", tld: tld, kind: kind}

  defp insert_at(chars, i, c) do
    {before, after_chars} = Enum.split(chars, i)
    before ++ [c | after_chars]
  end

  # =============================================================================
  # Permutation Generators
  # =============================================================================

  # Addition: Append a-z to domain
  defp addition(domain, tld) do
    Stream.map(@ascii_lower, &perm(domain <> <<&1>>, tld, "Addition"))
  end

  # Bitsquatting: Single bit flips at each position
  defp bitsquatting(domain, tld) do
    chars = String.to_charlist(domain)

    for {c, idx} <- Enum.with_index(chars),
        mask <- 0..7,
        squatted = Bitwise.bxor(c, Bitwise.bsl(1, mask)),
        squatted in ?a..?z or squatted in ?0..?9 or squatted == ?- do
      chars |> List.replace_at(idx, squatted) |> perm(tld, "Bitsquatting")
    end
  end

  # Hyphenation: Add hyphens between characters
  defp hyphenation(domain, tld) do
    chars = String.to_charlist(domain)

    for i <- 1..(length(chars) - 1)//1 do
      chars |> insert_at(i, ?-) |> perm(tld, "Hyphenation")
    end
  end

  # Hyphenation at TLD boundary (for multi-part TLDs)
  defp hyphenation_tld_boundary(domain, tld) do
    case String.split(tld, ".", parts: 2) do
      [first, rest] -> [perm("#{domain}-#{first}", rest, "HyphenationTldBoundary")]
      _ -> []
    end
  end

  # Insertion: Insert keyboard-adjacent characters
  defp insertion(domain, tld) do
    chars = String.to_charlist(domain)

    for {c, i} <- Enum.with_index(chars),
        adj <- Map.get(@qwerty_adjacents, c, []),
        pos <- [i, i + 1] do
      chars |> insert_at(pos, adj) |> perm(tld, "Insertion")
    end
  end

  # Omission: Remove single characters
  defp omission(domain, tld) do
    chars = String.to_charlist(domain)

    for i <- 0..(length(chars) - 1)//1 do
      chars |> List.delete_at(i) |> perm(tld, "Omission")
    end
  end

  # Repetition: Repeat characters
  defp repetition(domain, tld) do
    chars = String.to_charlist(domain)

    for {c, i} <- Enum.with_index(chars), c in ?a..?z or c in ?0..?9 do
      chars |> insert_at(i + 1, c) |> perm(tld, "Repetition")
    end
  end

  # Replacement: Replace with keyboard-adjacent characters
  defp replacement(domain, tld) do
    chars = String.to_charlist(domain)

    for {c, i} <- Enum.with_index(chars),
        adj <- Map.get(@qwerty_adjacents, c, []) do
      chars |> List.replace_at(i, adj) |> perm(tld, "Replacement")
    end
  end

  # Subdomain: Add dots to create fake subdomains
  defp subdomain(domain, tld) do
    chars = List.to_tuple(String.to_charlist(domain))

    for i <- 1..(tuple_size(chars) - 1)//1,
        elem(chars, i - 1) not in [?-, ?.],
        elem(chars, i) not in [?-, ?.] do
      chars |> Tuple.to_list() |> insert_at(i, ?.) |> perm(tld, "Subdomain")
    end
  end

  # Transposition: Swap adjacent characters
  defp transposition(domain, tld) do
    chars = String.to_charlist(domain)
    tuple = List.to_tuple(chars)

    for i <- 0..(tuple_size(tuple) - 2)//1,
        c1 = elem(tuple, i),
        c2 = elem(tuple, i + 1),
        c1 != c2 do
      chars
      |> List.replace_at(i, c2)
      |> List.replace_at(i + 1, c1)
      |> perm(tld, "Transposition")
    end
  end

  # Vowel Swap: Replace vowels with other vowels
  defp vowel_swap(domain, tld) do
    chars = String.to_charlist(domain)

    for {c, i} <- Enum.with_index(chars),
        c in @vowels_lower,
        vowel <- @vowels_lower,
        vowel != c do
      chars |> List.replace_at(i, vowel) |> perm(tld, "VowelSwap")
    end
  end

  # Vowel Shuffle: All vowel combinations over the first N vowels
  defp vowel_shuffle(domain, tld) do
    chars = String.to_charlist(domain)

    positions =
      for({c, i} <- Enum.with_index(chars), c in @vowels_lower, do: i)
      |> Enum.take(@vowel_shuffle_ceiling)

    case positions do
      [] ->
        []

      _ ->
        slot = positions |> Enum.with_index() |> Map.new()

        for combo <- cartesian_power(@vowels_lower, length(positions)) do
          combo = List.to_tuple(combo)

          chars
          |> Enum.with_index()
          |> Enum.map(fn {c, i} ->
            case slot do
              %{^i => s} -> elem(combo, s)
              _ -> c
            end
          end)
          |> perm(tld, "VowelShuffle")
        end
    end
  end

  defp cartesian_power(list, n), do: cartesian_power(list, n, [[]])
  defp cartesian_power(_list, 0, acc), do: acc

  defp cartesian_power(list, n, acc) do
    cartesian_power(list, n - 1, for(item <- list, rest <- acc, do: [item | rest]))
  end

  # Double Vowel Insertion: Insert vowel between adjacent vowels
  defp double_vowel_insertion(domain, tld) do
    chars = String.to_charlist(domain)
    tuple = List.to_tuple(chars)

    for i <- 0..(tuple_size(tuple) - 2)//1,
        elem(tuple, i) in @vowels_lower and elem(tuple, i + 1) in @vowels_lower,
        inserted <- @vowels_lower do
      chars |> insert_at(i + 1, inserted) |> perm(tld, "DoubleVowelInsertion")
    end
  end

  # Keyword: Common phishing keywords
  defp keyword(domain, tld, priority_only) do
    keywords = if priority_only, do: @priority_keywords, else: @keywords

    Stream.flat_map(keywords, fn kw ->
      [
        perm("#{domain}-#{kw}", tld, "Keyword"),
        perm("#{domain}#{kw}", tld, "Keyword"),
        perm("#{kw}-#{domain}", tld, "Keyword"),
        perm("#{kw}#{domain}", tld, "Keyword")
      ]
    end)
  end

  # TLD Swap: Different TLDs
  defp tld_swap(domain, tlds) do
    Stream.map(tlds, &perm(domain, &1, "Tld"))
  end

  # Faux TLD: TLD-like strings appended to the name
  defp faux_tld(domain, tld, tlds) do
    Stream.flat_map(tlds, fn tld_var ->
      faux = String.replace(tld_var, ".", "-")
      [perm("#{domain}-#{faux}", tld, "FauxTld"), perm("#{domain}#{faux}", tld, "FauxTld")]
    end)
  end

  # Mapped: Character to look-alike mappings, applied at each occurrence
  defp mapped(domain, tld) do
    for {key, values} <- @mapped,
        {pos, len} <- :binary.matches(domain, key),
        value <- values do
      before = binary_part(domain, 0, pos)
      rest = binary_part(domain, pos + len, byte_size(domain) - pos - len)
      perm(before <> value <> rest, tld, "Mapped")
    end
  end

  # Homoglyph: Visually similar characters
  defp homoglyph(domain, tld) do
    chars = String.to_charlist(domain)

    for {c, i} <- Enum.with_index(chars),
        g <- Map.get(@homoglyphs, c, []) do
      chars |> List.replace_at(i, g) |> perm(tld, "Homoglyph")
    end
  end
end
