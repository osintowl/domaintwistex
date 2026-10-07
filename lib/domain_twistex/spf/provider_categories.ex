defmodule DomainTwistex.SPF.ProviderCategories do
  @moduledoc """
  Aggregates all SPF provider category definitions.
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

  @doc """
  Returns all provider categories with their providers.
  """
  @spec categories() :: map()
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
end
