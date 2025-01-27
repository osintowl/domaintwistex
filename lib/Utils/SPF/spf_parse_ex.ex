defmodule DomainTwistex.SPF do
  alias DomainTwistex.SPF.ProviderCategories

  @moduledoc """
  DomainTwistex.SPF provides functionality to parse and explain SPF (Sender Policy Framework) records
  with enhanced categorization for template rendering.

  Copyright (c) 2024, [Nix2Intel]
  All rights reserved.
  This source code is licensed under the BSD-3-Clause license.
  """

  @provider_categories ProviderCategories.categories()

  @doc """
  Parses TXT records and extracts SPF information.
  Returns a map containing parsed SPF record details and categorized providers.
  """
  def parse_txt_records({:ok, records}) do
    records
    |> Enum.find(fn record ->
      String.starts_with?(record, "v=spf1")
    end)
    |> parse_spf_record()
  end

  @doc """
  Parses a single SPF record and returns structured data with provider categorization.
  """
  def parse_spf_record(nil), do: {:error, "No SPF record found"}

  def parse_spf_record(record) do
    parts =
      record
      |> String.split(" ")
      # Remove v=spf1
      |> Enum.drop(1)

    mechanisms =
      parts
      |> Enum.map(&parse_mechanism/1)
      |> Enum.reject(&is_nil/1)

    %{
      version: "spf1",
      mechanisms: mechanisms,
      all_mechanism: get_all_mechanism(parts),
      includes: get_includes(mechanisms),
      lookup_count: count_lookups(mechanisms),
      raw_record: record,
      providers_by_category: categorize_providers(mechanisms)
    }
  end

  defp get_provider_info(domain) do
    # Normalize domain by removing leading underscores and getting base domain
    normalized_domain =
      domain
      |> String.replace_prefix("_", "")
      |> get_base_domain()

    Enum.find_value(@provider_categories, fn {category, category_info} ->
      if Map.has_key?(category_info.providers, normalized_domain) do
        provider = category_info.providers[normalized_domain]

        %{
          category: category,
          category_name: category_info.name,
          category_description: category_info.description,
          provider_name: provider.name,
          provider_description: provider.description,
          domain: domain,
          base_domain: normalized_domain
        }
      end
    end) ||
      %{
        category: :unknown,
        category_name: "Unknown Provider",
        category_description: "Unrecognized email service provider",
        provider_name: domain,
        provider_description: "No information available",
        domain: domain
      }
  end

  defp get_base_domain(domain) do
    domain
    |> String.split(".")
    |> Enum.reverse()
    |> Enum.take(2)
    |> Enum.reverse()
    |> Enum.join(".")
  end

  @doc """
  Lists all available provider categories with their providers.
  """
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

  defp parse_mechanism(mechanism) do
    cond do
      String.starts_with?(mechanism, "include:") ->
        {:include, String.replace(mechanism, "include:", "")}

      String.starts_with?(mechanism, "ip4:") ->
        {:ip4, String.replace(mechanism, "ip4:", "")}

      String.starts_with?(mechanism, "ip6:") ->
        {:ip6, String.replace(mechanism, "ip6:", "")}

      String.starts_with?(mechanism, "a:") ->
        {:a, String.replace(mechanism, "a:", "")}

      String.starts_with?(mechanism, "mx:") ->
        {:mx, String.replace(mechanism, "mx:", "")}

      mechanism in ["~all", "-all", "?all", "+all"] ->
        nil

      true ->
        {:unknown, mechanism}
    end
  end

  defp get_all_mechanism(parts) do
    Enum.find(parts, "~all", fn part ->
      part in ["~all", "-all", "?all", "+all"]
    end)
  end

  defp get_includes(mechanisms) do
    mechanisms
    |> Enum.filter(fn
      {:include, _} -> true
      _ -> false
    end)
    |> Enum.map(fn {:include, domain} -> domain end)
  end

  defp count_lookups(mechanisms) do
    mechanisms
    |> Enum.count(fn
      {:include, _} -> true
      {:mx, _} -> true
      {:a, _} -> true
      _ -> false
    end)
  end

  defp categorize_providers(mechanisms) do
    mechanisms
    |> Enum.map(fn
      {:include, domain} -> get_provider_info(domain)
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.group_by(& &1.category_name)
  end

  # defp explain_all_mechanism("~all"),
  #   do: "Softly fails emails from all other sources (marks as suspicious but usually delivers)"

  # defp explain_all_mechanism("-all"),
  #   do: "Strictly blocks emails from all other sources (recommended for security)"

  # defp explain_all_mechanism("?all"),
  #   do: "Neutral - takes no position on emails from other sources (not recommended)"

  # defp explain_all_mechanism("+all"),
  #   do: "Allows emails from all sources (dangerous, not recommended)"

  # defp explain_lookups(count) when count > 10, do: "WARNING: Exceeds 10 lookup limit!"
  # defp explain_lookups(count) when count > 7, do: "Approaching lookup limit"
  # defp explain_lookups(_), do: "Within safe limits"

  # defp explain_other_mechanisms(mechanisms) do
  #   mechanisms
  #   |> Enum.reject(fn
  #     {:include, _} -> true
  #     _ -> false
  #   end)
  #   |> Enum.map(fn
  #     {:ip4, ip} -> %{type: :ip4, value: ip, description: "Allows specific IPv4 address"}
  #     {:ip6, ip} -> %{type: :ip6, value: ip, description: "Allows specific IPv6 address"}
  #     {:a, domain} -> %{type: :a, value: domain, description: "Allows A record from domain"}
  #     {:mx, domain} -> %{type: :mx, value: domain, description: "Allows MX record from domain"}
  #     {:unknown, mech} -> %{type: :unknown, value: mech, description: "Unknown mechanism"}
  #   end)
  # end
end
