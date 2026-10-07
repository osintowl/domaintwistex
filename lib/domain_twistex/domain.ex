defmodule DomainTwistex.Domain do
  @moduledoc """
  Domain name normalization and public-suffix-aware parsing.

  Uses the bundled public suffix list (`priv/tlds.txt`) to split a host into
  its registrable name and suffix, so `mail.example.co.uk` is treated as
  `example` + `co.uk` rather than `mail` + `example.co.uk`.
  """

  alias DomainTwistex.IDNA

  @external_resource suffixes_path = Path.join(:code.priv_dir(:domaintwistex), "tlds.txt")

  @suffixes suffixes_path
            |> File.read!()
            |> String.split("\n", trim: true)
            |> Enum.map(&String.trim/1)
            |> Enum.reject(&(&1 == "" or String.starts_with?(&1, ["//", "*", "!"])))
            |> MapSet.new()

  @doc """
  Normalizes user input into a bare lowercase hostname.

  Strips whitespace, URL scheme, userinfo, path, query, port, and trailing dot,
  and NFC-normalizes Unicode.

  ## Examples

      iex> DomainTwistex.Domain.normalize(" HTTPS://WWW.Example.COM:443/login?x=1 ")
      "www.example.com"

  """
  @spec normalize(String.t()) :: String.t()
  def normalize(input) when is_binary(input) do
    input
    |> String.trim()
    |> String.downcase()
    |> then(&Regex.replace(~r{^[a-z][a-z0-9+.\-]*://}, &1, ""))
    |> String.split(["/", "?", "#"], parts: 2)
    |> hd()
    |> String.split("@")
    |> List.last()
    |> then(&Regex.replace(~r/:\d+$/, &1, ""))
    |> String.trim_trailing(".")
    |> :unicode.characters_to_nfc_binary()
  end

  @doc """
  Splits a hostname into `{name, suffix}` using the public suffix list.

  Any labels left of the registrable name are discarded. A bare label with
  no suffix is treated as `.com`.

  ## Examples

      iex> DomainTwistex.Domain.split("mail.example.co.uk")
      {"example", "co.uk"}

      iex> DomainTwistex.Domain.split("example")
      {"example", "com"}

  """
  @spec split(String.t()) :: {String.t(), String.t()}
  def split(host) do
    case String.split(host, ".") do
      [single] ->
        {single, "com"}

      labels ->
        count = length(labels)

        index =
          Enum.find(1..(count - 1)//1, fn i ->
            labels |> Enum.drop(i) |> Enum.join(".") |> suffix?()
          end) || count - 1

        {Enum.at(labels, index - 1), labels |> Enum.drop(index) |> Enum.join(".")}
    end
  end

  @doc """
  Returns the registrable domain (`name.suffix`) for a hostname.

  ## Examples

      iex> DomainTwistex.Domain.registrable("_spf.mail.google.com")
      "google.com"

  """
  @spec registrable(String.t()) :: String.t()
  def registrable(host) do
    {name, suffix} = split(host)
    "#{name}.#{suffix}"
  end

  @doc """
  Returns the part of a hostname to the left of its public suffix.

  ## Examples

      iex> DomainTwistex.Domain.stem("ex.ample.co.uk")
      "ex.ample"

  """
  @spec stem(String.t()) :: String.t()
  def stem(host) do
    {_name, suffix} = split(host)

    if String.ends_with?(host, "." <> suffix) do
      String.slice(host, 0, String.length(host) - String.length(suffix) - 1)
    else
      host
    end
  end

  @doc """
  Returns true if the string is a known public suffix.
  """
  @spec suffix?(String.t()) :: boolean()
  def suffix?(candidate) do
    MapSet.member?(@suffixes, candidate) or
      (not IDNA.ascii?(candidate) and MapSet.member?(@suffixes, IDNA.to_ascii(candidate)))
  end
end
