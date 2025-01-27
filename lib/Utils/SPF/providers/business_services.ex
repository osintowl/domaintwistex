defmodule DomainTwistex.SPF.Providers.BusinessServices do

  @moduledoc """
  Defines business service provider domains commonly found in SPF records.
  """

  def providers do
    %{
      "service-now.com" => %{
        name: "ServiceNow",
        description: "Enterprise service management platform",
        type: :primary,
        market_segment: :enterprise_service,
        spf_mechanisms: [
          "include:service-now.com",
          "include:b.spf.service-now.com",
          "include:c.spf.service-now.com",
          "include:d.spf.service-now.com"
        ],
        common_records: [
          "v=spf1 include:service-now.com -all"
        ]
      },

      "docusign.net" => %{
        name: "DocuSign",
        description: "Electronic signature and agreement cloud",
        type: :primary,
        market_segment: :document_management,
        spf_mechanisms: [
          "include:docusign.net",
          "include:spf.docusign.net"
        ],
        common_records: [
          "v=spf1 include:docusign.net -all"
        ]
      },

      "workday.com" => %{
        name: "Workday",
        description: "Enterprise cloud applications for finance and HR",
        type: :primary,
        market_segment: :enterprise_management,
        spf_mechanisms: [
          "include:workday.com",
          "include:myworkday.com"
        ],
        common_records: [
          "v=spf1 include:workday.com -all"
        ]
      },

      "zendesk.com" => %{
        name: "Zendesk",
        description: "Customer service and engagement platform",
        type: :primary,
        market_segment: :customer_service,
        spf_mechanisms: [
          "include:zendesk.com",
          "include:email.zendesk.com"
        ],
        common_records: [
          "v=spf1 include:zendesk.com -all"
        ]
      },

      "liveperson.net" => %{
        name: "LivePerson",
        description: "Conversational AI and messaging solutions",
        type: :primary,
        market_segment: :customer_engagement,
        spf_mechanisms: [
          "include:_spf.server.iad.liveperson.net",
          "include:_spf.server.lon.liveperson.net",
          "include:_spf.sales.liveperson.net"
        ],
        common_records: [
          "v=spf1 include:_spf.liveperson.net -all"
        ]
      },

      "sapsf.com" => %{
        name: "SAP SuccessFactors",
        description: "Human capital management suite",
        type: :primary,
        market_segment: :hr_management,
        spf_mechanisms: [
          "include:_spf-dc4.sapsf.com",
          "include:_spf-dc8.sapsf.com",
          "include:_spf-dc10.sapsf.com",
          "include:_spf-dc12.successfactors.com",
          "include:_spf-dc33.sapsf.eu"
        ],
        common_records: [
          "v=spf1 include:_spf-dc4.sapsf.com -all"
        ]
      }
    }
  end

end

