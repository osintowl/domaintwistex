defmodule DomainTwistex.SPF do
  @moduledoc """
  SPF (Sender Policy Framework) record parser with provider categorization.

  Parses SPF records (RFC 7208) from TXT DNS records, including qualifiers,
  modifiers (`redirect=`, `exp=`), and every mechanism type, and categorizes
  detected email service providers for security analysis.
  """

  alias DomainTwistex.Domain
  alias DomainTwistex.SPF.ProviderCategories

  @provider_categories ProviderCategories.categories()

  # domain => provider info, flattened once at compile time
  @providers_by_domain (for {category, info} <- @provider_categories,
                            {domain, provider} <- info.providers,
                            into: %{} do
                          {domain,
                           %{
                             category: category,
                             category_name: info.name,
                             category_description: info.description,
                             provider_name: provider.name,
                             provider_description: provider.description
                           }}
                        end)

  @mechanisms %{
    "all" => :all,
    "include" => :include,
    "a" => :a,
    "mx" => :mx,
    "ptr" => :ptr,
    "ip4" => :ip4,
    "ip6" => :ip6,
    "exists" => :exists
  }
  @lookup_mechanisms [:include, :a, :mx, :ptr, :exists]
  @qualifiers %{"+" => :pass, "-" => :fail, "~" => :softfail, "?" => :neutral}
  @max_lookups 10

  @type mechanism :: %{type: atom(), qualifier: atom(), value: String.t() | nil}

  @type spf_result :: %{
          version: String.t(),
          mechanisms: [mechanism()],
          modifiers: %{String.t() => String.t()},
          all_mechanism: String.t() | nil,
          includes: [String.t()],
          redirect: String.t() | nil,
          lookup_count: non_neg_integer(),
          raw_record: String.t(),
          providers_by_category: map(),
          warnings: [String.t()]
        }

  @doc """
  Parses TXT records and extracts SPF information.

  If several SPF records are published (a permerror per RFC 7208), the first
  is parsed and a warning is added.

  ## Returns

    Map containing parsed SPF record details and categorized providers,
    or `{:error, reason}` if no SPF record found.

  """
  @spec parse_txt_records({:ok, [String.t()]}) :: spf_result() | {:error, String.t()}
  def parse_txt_records({:ok, records}) do
    case Enum.filter(records, &spf_record?/1) do
      [] ->
        {:error, "No SPF record found"}

      [record] ->
        parse_spf_record(record)

      [record | _] = all ->
        record
        |> parse_spf_record()
        |> Map.update!(:warnings, &["multiple SPF records published (#{length(all)})" | &1])
    end
  end

  def parse_txt_records(_), do: {:error, "No SPF record found"}

  @doc """
  Parses a single SPF record and returns structured data with provider categorization.

  ## Examples

      iex> spf = DomainTwistex.SPF.parse_spf_record("v=spf1 include:_spf.google.com ~all")
      iex> spf.all_mechanism
      "~all"
      iex> spf.includes
      ["_spf.google.com"]

  """
  @spec parse_spf_record(String.t() | nil) :: spf_result() | {:error, String.t()}
  def parse_spf_record(nil), do: {:error, "No SPF record found"}

  def parse_spf_record(record) do
    terms = record |> String.split() |> Enum.drop(1)

    {mechanisms, modifiers} =
      Enum.reduce(terms, {[], %{}}, fn term, {mechs, mods} ->
        case parse_term(term) do
          {:modifier, key, value} -> {mechs, Map.put_new(mods, key, value)}
          mechanism -> {[mechanism | mechs], mods}
        end
      end)

    mechanisms = Enum.reverse(mechanisms)
    includes = for %{type: :include, value: v} <- mechanisms, v != nil, do: v
    redirect = modifiers["redirect"]

    lookup_count =
      Enum.count(mechanisms, &(&1.type in @lookup_mechanisms)) + if(redirect, do: 1, else: 0)

    all_mechanism =
      Enum.find_value(mechanisms, fn
        %{type: :all, qualifier: q} -> qualifier_prefix(q) <> "all"
        _ -> nil
      end)

    %{
      version: "spf1",
      mechanisms: mechanisms,
      modifiers: modifiers,
      all_mechanism: all_mechanism,
      includes: includes,
      redirect: redirect,
      lookup_count: lookup_count,
      raw_record: record,
      providers_by_category: categorize_providers(includes ++ List.wrap(redirect)),
      warnings: warnings(mechanisms, all_mechanism, redirect, lookup_count)
    }
  end

  @doc """
  Lists all available provider categories with their providers.
  """
  @spec list_categories() :: [map()]
  def list_categories do
    @provider_categories
    |> Enum.map(fn {key, value} ->
      %{
        id: key,
        name: value.name,
        description: value.description,
        providers: Map.values(value.providers)
      }
    end)
  end

  # =============================================================================
  # Private Functions
  # =============================================================================

  defp spf_record?(txt) do
    case String.downcase(txt) do
      "v=spf1" -> true
      "v=spf1 " <> _ -> true
      _ -> false
    end
  end

  defp parse_term(term) do
    {qualifier, rest} =
      case term do
        <<q::binary-1, rest::binary>> when is_map_key(@qualifiers, q) -> {@qualifiers[q], rest}
        _ -> {:pass, term}
      end

    # Mechanism name ends at ":" or "/" (e.g. "a/24", "mx:host/24")
    [name | _] = String.split(rest, [":", "/", "="], parts: 2)
    name_lower = String.downcase(name)
    after_name = binary_part(rest, byte_size(name), byte_size(rest) - byte_size(name))

    cond do
      String.starts_with?(after_name, "=") and qualifier == :pass and term == rest ->
        {:modifier, name_lower, String.slice(after_name, 1..-1//1)}

      is_map_key(@mechanisms, name_lower) ->
        value =
          case after_name do
            ":" <> v -> v
            "" -> nil
            other -> other
          end

        %{type: @mechanisms[name_lower], qualifier: qualifier, value: value}

      true ->
        %{type: :unknown, qualifier: qualifier, value: term}
    end
  end

  defp qualifier_prefix(:pass), do: "+"
  defp qualifier_prefix(:fail), do: "-"
  defp qualifier_prefix(:softfail), do: "~"
  defp qualifier_prefix(:neutral), do: "?"

  defp warnings(mechanisms, all_mechanism, redirect, lookup_count) do
    [
      {lookup_count > @max_lookups, "exceeds #{@max_lookups} DNS lookup limit (#{lookup_count})"},
      {all_mechanism == "+all", "+all permits any sender"},
      {all_mechanism == nil and redirect == nil, "no all mechanism or redirect (defaults to neutral)"},
      {Enum.any?(mechanisms, &(&1.type == :ptr)), "uses deprecated ptr mechanism"},
      {Enum.any?(mechanisms, &(&1.type == :unknown)), "contains unrecognized terms"}
    ]
    |> Enum.filter(&elem(&1, 0))
    |> Enum.map(&elem(&1, 1))
  end

  defp categorize_providers(domains) do
    domains
    |> Enum.map(&get_provider_info/1)
    |> Enum.group_by(& &1.category_name)
  end

  defp get_provider_info(domain) do
    domain = String.downcase(domain)
    base = domain |> String.trim_leading("_") |> Domain.registrable()

    case Map.get(@providers_by_domain, domain) || Map.get(@providers_by_domain, base) do
      nil ->
        %{
          category: :unknown,
          category_name: "Unknown Provider",
          category_description: "Unrecognized email service provider",
          provider_name: domain,
          provider_description: "No information available",
          domain: domain,
          base_domain: base
        }

      info ->
        Map.merge(info, %{domain: domain, base_domain: base})
    end
  end
end
