defmodule DomainTwistex.Permutate do
  @moduledoc """
  Pure Elixir domain permutation generator.

  Drop-in replacement for the Rust NIF `DomainTwistex.Utils.generate_permutations/1`.
  Generates all 18 permutation types matching twistrs.

  Addition, Bitsquatting, Hyphenation, HyphenationTldBoundary, Insertion,
  Omission, Repetition, Replacement, Subdomain, Transposition, VowelSwap,
  VowelShuffle, DoubleVowelInsertion, Keyword, Tld, FauxTld, Mapped, Homoglyph
  """

  @vowels [?a, ?e, ?i, ?o, ?u, ?A, ?E, ?I, ?O, ?U]
  @vowel_shuffle_ceiling 6
  @ascii_lower [?a, ?b, ?c, ?d, ?e, ?f, ?g, ?h, ?i, ?j, ?k, ?l, ?m, ?n, ?o, ?p, ?q, ?r, ?s, ?t, ?u, ?v, ?w, ?x, ?y, ?z]

  @homoglyphs %{
    ?a => ~C"àáâãäåɑạǎăȧą",
    ?b => ~C"dʙɓḃḅḇƅ",
    ?c => ~C"eƈċćçčĉo",
    ?d => ~C"bɗđďɖḑḋḍḏḓ",
    ?e => ~C"céèêëēĕěėẹęȩɇḛ",
    ?f => ~C"ƒḟ",
    ?g => ~C"qɢɡġğǵģĝǧǥ",
    ?h => ~C"ĥȟħɦḧḩⱨḣḥḫẖ",
    ?i => ~C"1líìïıɩǐĭỉịɨȋī",
    ?j => ~C"ʝɉ",
    ?k => ~C"ḳḵⱪķ",
    ?l => ~C"1iɫł",
    ?m => ~C"nṁṃᴍɱḿ",
    ?n => ~C"mrńṅṇṉñņǹňꞑ",
    ?o => ~C"0ȯọỏơóö",
    ?p => ~C"ƿƥṕṗ",
    ?q => ~C"gʠ",
    ?r => ~C"ʀɼɽŕŗřɍɾȓȑṙṛṟ",
    ?s => ~C"ʂśṣṡșŝš",
    ?t => ~C"ţŧṫṭțƫ",
    ?u => ~C"ᴜǔŭüʉùúûũūųưůűȕȗụ",
    ?v => ~C"ṿⱱᶌṽⱴ",
    ?w => ~C"ŵẁẃẅⱳẇẉẘ",
    ?y => ~C"ʏýÿŷƴȳɏỿẏỵ",
    ?z => ~C"ʐżźᴢƶẓẕⱬ"
  }

  @mapped %{
    "a" => ["4"], "b" => ["8", "6"], "c" => [], "d" => ["cl"],
    "e" => ["3"], "f" => ["ph"], "g" => ["9", "6"], "h" => [],
    "i" => ["1", "l"], "j" => [], "k" => [], "l" => ["1", "i"],
    "m" => ["rn", "nn"], "n" => [], "o" => ["0"], "p" => [],
    "q" => ["9"], "r" => [], "s" => ["5", "z"], "t" => ["7"],
    "u" => ["v"], "v" => ["u"], "w" => ["vv"], "x" => [],
    "y" => [], "z" => ["2", "s"], "0" => ["o"], "1" => ["i", "l"],
    "2" => ["z"], "3" => ["e"], "4" => ["a"], "5" => ["s"],
    "6" => ["b", "g"], "7" => ["t"], "8" => ["b"], "9" => ["g", "q"],
    "ck" => ["kk"], "oo" => ["00"]
  }

  @keyboard_layouts [
    %{?1 => "2q", ?2 => "3wq1", ?3 => "4ew2", ?4 => "5re3", ?5 => "6tr4",
      ?6 => "7yt5", ?7 => "8uy6", ?8 => "9iu7", ?9 => "0oi8", ?0 => "po9",
      ?q => "12wa", ?w => "3esaq2", ?e => "4rdsw3", ?r => "5tfde4",
      ?t => "6ygfr5", ?y => "7uhgt6", ?u => "8ijhy7", ?i => "9okju8",
      ?o => "0plki9", ?p => "lo0", ?a => "qwsz", ?s => "edxzaw",
      ?d => "rfcxse", ?f => "tgvcdr", ?g => "yhbvft", ?h => "ujnbgy",
      ?j => "ikmnhu", ?k => "olmji", ?l => "kop", ?z => "asx",
      ?x => "zsdc", ?c => "xdfv", ?v => "cfgb", ?b => "vghn",
      ?n => "bhjm", ?m => "njk"},
    %{?1 => "2q", ?2 => "3wq1", ?3 => "4ew2", ?4 => "5re3", ?5 => "6tr4",
      ?6 => "7zt5", ?7 => "8uz6", ?8 => "9iu7", ?9 => "0oi8", ?0 => "po9",
      ?q => "12wa", ?w => "3esaq2", ?e => "4rdsw3", ?r => "5tfde4",
      ?t => "6zgfr5", ?z => "7uhgt6", ?u => "8ijhz7", ?i => "9okju8",
      ?o => "0plki9", ?p => "lo0", ?a => "qwsy", ?s => "edxyaw",
      ?d => "rfcxse", ?f => "tgvcdr", ?g => "zhbvft", ?h => "ujnbgz",
      ?j => "ikmnhu", ?k => "olmji", ?l => "kop", ?y => "asx",
      ?x => "ysdc", ?c => "xdfv", ?v => "cfgb", ?b => "vghn",
      ?n => "bhjm", ?m => "njk"},
    %{?1 => "2a", ?2 => "3za1", ?3 => "4ez2", ?4 => "5re3", ?5 => "6tr4",
      ?6 => "7yt5", ?7 => "8uy6", ?8 => "9iu7", ?9 => "0oi8", ?0 => "po9",
      ?a => "2zq1", ?z => "3esqa2", ?e => "4rdsz3", ?r => "5tfde4",
      ?t => "6ygfr5", ?y => "7uhgt6", ?u => "8ijhy7", ?i => "9okju8",
      ?o => "0plki9", ?p => "lo0m", ?q => "zswa", ?s => "edxwqz",
      ?d => "rfcxse", ?f => "tgvcdr", ?g => "yhbvft", ?h => "ujnbgy",
      ?j => "iknhu", ?k => "olji", ?l => "kopm", ?m => "lp",
      ?w => "sxq", ?x => "wsdc", ?c => "xdfv", ?v => "cfgb",
      ?b => "vghn", ?n => "bhj"}
  ]

  @tlds File.read!(Path.join([:code.priv_dir(:domaintwistex), "tlds.txt"]))
        |> String.split("\n", trim: true)
  @keywords File.read!(Path.join([:code.priv_dir(:domaintwistex), "keywords.txt"]))
             |> String.split("\n", trim: true)

  @doc """
  Generates all domain permutations for a given FQDN.
  Returns a list of maps with :fqdn, :tld, and :kind keys,
  matching the output format of the Rust NIF.

  Options:
    - `:faux_tld` - include FauxTld permutations (default: false, adds ~14K entries)
    - `:double_vowel` - include DoubleVowelInsertion (default: true)
    - `:vowel_shuffle` - include VowelShuffle (default: true)
  """
  def generate_permutations(fqdn, opts \\ []) do
    include_faux_tld = Keyword.get(opts, :faux_tld, false)
    include_double_vowel = Keyword.get(opts, :double_vowel, true)
    include_vowel_shuffle = Keyword.get(opts, :vowel_shuffle, true)

    {domain, tld} = parse_domain(fqdn)

    base =
      addition(domain, tld)
      |> Stream.concat(bitsquatting(fqdn))
      |> Stream.concat(hyphenation(fqdn))
      |> Stream.concat(hyphenation_tld_boundary(domain, tld))
      |> Stream.concat(insertion(fqdn))
      |> Stream.concat(omission(fqdn))
      |> Stream.concat(repetition(fqdn))
      |> Stream.concat(replacement(fqdn))
      |> Stream.concat(subdomain(fqdn))
      |> Stream.concat(transposition(fqdn))
      |> Stream.concat(vowel_swap(fqdn))
      |> Stream.concat(keyword(domain, tld))
      |> Stream.concat(tld(domain))
      |> Stream.concat(mapped(domain, tld))
      |> Stream.concat(homoglyph(fqdn))

    with_extras =
      base
      |> maybe_concat(include_vowel_shuffle, vowel_shuffle(domain, tld))
      |> maybe_concat(include_double_vowel, double_vowel_insertion(fqdn))
      |> maybe_concat(include_faux_tld, faux_tld(domain, tld))

    with_extras
    |> Enum.uniq_by(& &1.fqdn)
    |> Enum.reject(&invalid_fqdn?/1)
  end

  defp invalid_fqdn?(%{fqdn: fqdn}) do
    fqdn == "" or String.contains?(fqdn, "..") or String.starts_with?(fqdn, ".") or
      String.ends_with?(fqdn, ".") or String.contains?(fqdn, "--")
  end

  defp maybe_concat(stream, true, extras), do: Stream.concat(stream, extras)
  defp maybe_concat(stream, false, _extras), do: stream

  defp parse_domain(fqdn) do
    case String.split(fqdn, ".", parts: 2) do
      [domain, tld] -> {domain, tld}
      _ -> {fqdn, "com"}
    end
  end

  defp extract_tld(fqdn) do
    case String.split(fqdn, ".", parts: 2) do
      [_, tld] -> tld
      _ -> ""
    end
  end

  defp char_lower(c) when c >= ?A and c <= ?Z, do: c + 32
  defp char_lower(c), do: c

  # --- Addition ---

  defp addition(domain, tld) do
    Stream.map(@ascii_lower, fn c ->
      %{fqdn: "#{domain}#{c}.#{tld}", tld: tld, kind: "Addition"}
    end)
  end

  # --- Bitsquatting ---

  defp bitsquatting(fqdn) do
    chars = String.to_charlist(fqdn)
    len = length(chars)

    for c <- chars,
        mask_index <- 0..7,
        squatted = Bitwise.bxor(c, Bitwise.bsl(1, mask_index)),
        squatted in ?a..?z or squatted in ?0..?9 or squatted == ?-,
        idx <- 1..(len - 1) do
      {before, after_chars} = Enum.split(chars, idx)
      new_fqdn = List.to_string(before ++ [squatted] ++ after_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Bitsquatting"}
    end
  end

  # --- Hyphenation ---

  defp hyphenation(fqdn) do
    chars = String.to_charlist(fqdn)

    Stream.unfold({chars, 1}, fn
      {_, i} when i >= length(chars) -> nil
      {c, i} -> {{c, i}, {c, i + 1}}
    end)
    |> Stream.map(fn {_c, i} ->
      {before, after_chars} = Enum.split(chars, i)
      new_fqdn = List.to_string(before ++ [?-] ++ after_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Hyphenation"}
    end)
  end

  # --- Hyphenation TLD Boundary ---

  defp hyphenation_tld_boundary(domain, tld) do
    if String.contains?(tld, ".") do
      [%{fqdn: "#{domain}-#{tld}", tld: tld, kind: "Hyphenation"}]
    else
      []
    end
  end

  # --- Insertion ---

  defp insertion(fqdn) do
    chars = String.to_charlist(fqdn)
    len = length(chars)

    for i <- 0..(len - 2),
        layout <- @keyboard_layouts,
        c = Enum.at(chars, i + 1),
        adjacents = Map.get(layout, c, ""),
        keyboard_char <- String.to_charlist(adjacents) do
      {before, after_chars} = Enum.split(chars, i)
      new_fqdn = List.to_string(before ++ [keyboard_char] ++ after_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Insertion"}
    end
  end

  # --- Omission ---

  defp omission(fqdn) do
    chars = String.to_charlist(fqdn)

    for i <- 0..(length(chars) - 1) do
      new_fqdn = List.to_string(List.delete_at(chars, i))
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Omission"}
    end
  end

  # --- Repetition ---

  defp repetition(fqdn) do
    chars = String.to_charlist(fqdn)

    for {c, i} <- Enum.with_index(chars),
        c >= ?a and c <= ?z or c >= ?A and c <= ?Z do
      {before, after_chars} = Enum.split(chars, i + 1)
      new_fqdn = List.to_string(before ++ [c] ++ after_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Repetition"}
    end
  end

  # --- Replacement ---

  defp replacement(fqdn) do
    chars = String.to_charlist(fqdn)
    max = max(length(chars) - 2, 0)

    for i <- 1..max,
        layout <- @keyboard_layouts,
        c = Enum.at(chars, i),
        adjacents = Map.get(layout, c, ""),
        keyboard_char <- String.to_charlist(adjacents) do
      new_chars = List.replace_at(chars, i, keyboard_char)
      new_fqdn = List.to_string(new_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Replacement"}
    end
  end

  # --- Subdomain ---

  defp subdomain(fqdn) do
    chars = String.to_charlist(fqdn)
    len = length(chars)

    for i <- 0..max(len - 3, 0),
        c1 = Enum.at(chars, i),
        c2 = Enum.at(chars, i + 1, ?\0),
        c1 != ?- and c1 != ?. and c2 != ?. do
      {before, after_chars} = Enum.split(chars, i + 1)
      new_fqdn = List.to_string(before ++ [?.] ++ after_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Subdomain"}
    end
  end

  # --- Transposition ---

  defp transposition(fqdn) do
    chars = String.to_charlist(fqdn)

    for i <- 0..(length(chars) - 2),
        c1 = Enum.at(chars, i),
        c2 = Enum.at(chars, i + 1),
        c1 != c2 do
      new_chars = List.replace_at(chars, i, c2) |> List.replace_at(i + 1, c1)
      new_fqdn = List.to_string(new_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Transposition"}
    end
  end

  # --- Vowel Swap ---

  defp vowel_swap(fqdn) do
    chars = String.to_charlist(fqdn)

    for {c, i} <- Enum.with_index(chars),
        char_lower(c) in @vowels,
        vowel <- @vowels,
        vowel != c do
      new_fqdn = List.to_string(List.replace_at(chars, i, vowel))
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "VowelSwap"}
    end
  end

  # --- Vowel Shuffle ---

  defp vowel_shuffle(domain, tld) do
    domain_chars = String.to_charlist(domain)
    vowel_positions = for {c, i} <- Enum.with_index(domain_chars), c in @vowels, do: i
    n = min(length(vowel_positions), @vowel_shuffle_ceiling)

    if n == 0 do
      []
    else
      products = cartesian_power(@vowels, n)

      for replacement <- products do
        label = domain_chars
        |> Enum.with_index()
        |> Enum.map(fn {c, i} ->
          pos_idx = Enum.find_index(vowel_positions, &(&1 == i))
          if pos_idx != nil and pos_idx < n do
            Enum.at(replacement, pos_idx)
          else
            c
          end
        end)
        %{fqdn: "#{List.to_string(label)}.#{tld}", tld: tld, kind: "VowelShuffle"}
      end
    end
  end

  defp cartesian_power(list, n), do: cartesian_power(list, n, [[]])
  defp cartesian_power(_list, 0, acc), do: acc
  defp cartesian_power(list, n, acc) do
    new_acc = for item <- list, rest <- acc, do: [item | rest]
    cartesian_power(list, n - 1, new_acc)
  end

  # --- Double Vowel Insertion ---

  defp double_vowel_insertion(fqdn) do
    chars = String.to_charlist(fqdn)

    for i <- 0..(length(chars) - 2),
        c1 = Enum.at(chars, i),
        c2 = Enum.at(chars, i + 1),
        char_lower(c1) in @vowels and char_lower(c2) in @vowels,
        inserted <- @vowels do
      {before, after_chars} = Enum.split(chars, i + 1)
      new_fqdn = List.to_string(before ++ [inserted] ++ after_chars)
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "DoubleVowelInsertion"}
    end
  end

  # --- Keyword ---

  defp keyword(domain, tld) do
    for kw <- @keywords do
      [
        %{fqdn: "#{domain}-#{kw}.#{tld}", tld: tld, kind: "Keyword"},
        %{fqdn: "#{domain}#{kw}.#{tld}", tld: tld, kind: "Keyword"},
        %{fqdn: "#{kw}-#{domain}.#{tld}", tld: tld, kind: "Keyword"},
        %{fqdn: "#{kw}#{domain}.#{tld}", tld: tld, kind: "Keyword"}
      ]
    end
    |> List.flatten()
  end

  # --- TLD ---

  defp tld(domain) do
    Stream.map(@tlds, fn tld ->
      %{fqdn: "#{domain}.#{tld}", tld: tld, kind: "Tld"}
    end)
  end

  # --- Faux TLD ---

  defp faux_tld(domain, tld) do
    for tld_var <- @tlds do
      faux = String.replace(tld_var, ".", "-")
      [
        %{fqdn: "#{domain}-#{faux}.#{tld}", tld: tld, kind: "FauxTld"},
        %{fqdn: "#{domain}#{faux}.#{tld}", tld: tld, kind: "FauxTld"}
      ]
    end
    |> List.flatten()
  end

  # --- Mapped ---

  defp mapped(domain, tld) do
    Enum.flat_map(@mapped, fn
      {key, values} when key in ~w(ck oo) ->
        if String.contains?(domain, key) do
          Enum.map(values, fn mapped_value ->
            new_domain = String.replace(domain, key, mapped_value)
            %{fqdn: "#{new_domain}.#{tld}", tld: tld, kind: "Mapped"}
          end)
        else
          []
        end

      {key, values} ->
        if String.contains?(domain, key) do
          Enum.flat_map(values, fn mapped_value ->
            new_domain = String.replace(domain, key, mapped_value)
            [%{fqdn: "#{new_domain}.#{tld}", tld: tld, kind: "Mapped"}]
          end)
        else
          []
        end
    end)
  end

  # --- Homoglyph ---

  defp homoglyph(fqdn) do
    chars = String.to_charlist(fqdn)

    for {c, i} <- Enum.with_index(chars),
        glyphs <- [Map.get(@homoglyphs, c, [])],
        g <- glyphs do
      new_fqdn = List.to_string(List.replace_at(chars, i, g))
      %{fqdn: new_fqdn, tld: extract_tld(new_fqdn), kind: "Homoglyph"}
    end
  end
end