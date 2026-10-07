defmodule DomainTwistex.IDNA do
  @moduledoc """
  Minimal IDNA support: converts Unicode domain names to their ASCII
  (punycode, `xn--`) form per RFC 3492 so they can be resolved via DNS.

  Labels are lowercased and NFC-normalized before encoding. No IDNA2008
  validity checks are applied — disallowed code points are encoded anyway
  and will simply fail to resolve.
  """

  @base 36
  @tmin 1
  @tmax 26
  @skew 38
  @damp 700
  @initial_bias 72
  @initial_n 128

  @doc """
  Converts a (possibly Unicode) domain name to its ASCII form.

  ## Examples

      iex> DomainTwistex.IDNA.to_ascii("münchen.de")
      "xn--mnchen-3ya.de"

      iex> DomainTwistex.IDNA.to_ascii("example.com")
      "example.com"

  """
  @spec to_ascii(String.t()) :: String.t()
  def to_ascii(domain) do
    if ascii?(domain) do
      domain
    else
      domain
      |> String.split(".")
      |> Enum.map_join(".", &label_to_ascii/1)
    end
  end

  @doc """
  Returns true if the string contains only ASCII bytes.
  """
  @spec ascii?(String.t()) :: boolean()
  def ascii?(string), do: not String.match?(string, ~r/[^\x00-\x7F]/)

  @doc """
  Converts a single label to its ASCII form, prefixing `xn--` when needed.
  """
  @spec label_to_ascii(String.t()) :: String.t()
  def label_to_ascii(label) do
    if ascii?(label) do
      label
    else
      code_points =
        label
        |> String.downcase()
        |> :unicode.characters_to_nfc_binary()
        |> String.to_charlist()

      "xn--" <> encode(code_points)
    end
  end

  # RFC 3492 section 6.3
  defp encode(code_points) do
    basic = for c <- code_points, c < 128, do: c
    b = length(basic)
    out = if b > 0, do: basic ++ [?-], else: []

    code_points
    |> encode_loop(@initial_n, 0, @initial_bias, b, b, length(code_points), Enum.reverse(out))
    |> Enum.reverse()
    |> List.to_string()
  end

  defp encode_loop(_cps, _n, _delta, _bias, h, _b, total, out) when h >= total, do: out

  defp encode_loop(cps, n, delta, bias, h, b, total, out) do
    m = cps |> Enum.filter(&(&1 >= n)) |> Enum.min()
    delta = delta + (m - n) * (h + 1)

    {delta, bias, h, out} =
      Enum.reduce(cps, {delta, bias, h, out}, fn c, {delta, bias, h, out} ->
        cond do
          c < m ->
            {delta + 1, bias, h, out}

          c == m ->
            out = encode_int(delta, bias, @base, out)
            {0, adapt(delta, h + 1, h == b), h + 1, out}

          true ->
            {delta, bias, h, out}
        end
      end)

    encode_loop(cps, m + 1, delta + 1, bias, h, b, total, out)
  end

  defp encode_int(q, bias, k, out) do
    t =
      cond do
        k <= bias -> @tmin
        k >= bias + @tmax -> @tmax
        true -> k - bias
      end

    if q < t do
      [digit(q) | out]
    else
      next_q = div(q - t, @base - t)
      encode_int(next_q, bias, k + @base, [digit(t + rem(q - t, @base - t)) | out])
    end
  end

  defp digit(d) when d < 26, do: ?a + d
  defp digit(d), do: ?0 + d - 26

  defp adapt(delta, num_points, first?) do
    delta = if first?, do: div(delta, @damp), else: div(delta, 2)
    adapt_loop(delta + div(delta, num_points), 0)
  end

  defp adapt_loop(delta, k) when delta > div((@base - @tmin) * @tmax, 2),
    do: adapt_loop(div(delta, @base - @tmin), k + @base)

  defp adapt_loop(delta, k), do: k + div((@base - @tmin + 1) * delta, delta + @skew)
end
