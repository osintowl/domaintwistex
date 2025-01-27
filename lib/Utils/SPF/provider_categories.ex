defmodule DomainTwistex.SPF.ProviderCategories do
  @moduledoc """
  Defines categories for different types of email service providers and their SPF records.
  """

  alias DomainTwistex.SPF.Providers.{
    EmailWorkspaces,
    SecurityProviders,
    TransactionalEmail,
    CRMPlatforms,
    HostingProviders,
    BusinessServices,
    MarketingPlatforms
  }

  def categories do
    %{
      workspaces: %{
        name: "Email Workspaces",
        description: "Enterprise and business email hosting platforms",
        providers: EmailWorkspaces.providers()
      },
      security: %{
        name: "Email Security Providers",
        description: "Email security and filtering infrastructure",
        providers: SecurityProviders.providers()
      },
      transactional: %{
        name: "Transactional Email Providers",
        description: "Email sending infrastructure for transactional services",
        providers: TransactionalEmail.providers()
      },
      crm: %{
        name: "CRM Platforms",
        description: "Customer relationship management platforms with email capabilities",
        providers: CRMPlatforms.providers()
      },
      hosting: %{
        name: "Hosting Providers",
        description: "Web hosting companies offering email services",
        providers: HostingProviders.providers()
      },
      business: %{
        name: "Business Services",
        description: "Business service providers with email capabilities",
        providers: BusinessServices.providers()
      },
      marketing: %{
        name: "Marketing Services",
        description: "Marketing tools and services",
        providers: MarketingPlatforms.providers()
      }

    }
  end

  @doc """
  Returns all known providers across all categories
  """
  def all_providers do
    categories()
    |> Enum.flat_map(fn {_category, data} ->
      Map.values(data.providers)
    end)
  end

  @doc """
  Returns providers grouped by their market segment
  """
  def providers_by_market_segment do
    all_providers()
    |> Enum.group_by(fn provider ->
      Map.get(provider, :market_segment, :unknown)
    end)
  end

  @doc """
  Returns list of all unique provider domains
  """
  def known_domains do
    categories()
    |> Enum.flat_map(fn {_category, data} ->
      Map.keys(data.providers)
    end)
    |> Enum.uniq()
  end

  @doc """
  Returns category information for a specific provider domain
  """
  def get_provider_category(domain) do
    categories()
    |> Enum.find(fn {_category, data} ->
      Map.has_key?(data.providers, domain)
    end)
  end

  @doc """
  Returns list of all available market segments
  """
  def market_segments do
    [:enterprise, :business, :consumer, :security_focused, :infrastructure]
  end
end
