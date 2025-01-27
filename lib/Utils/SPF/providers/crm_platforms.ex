defmodule DomainTwistex.SPF.Providers.CRMPlatforms do

  @moduledoc """
  Defines CRM platform domains commonly found in SPF records.
  """

  def providers do
    %{
      # Salesforce
      "salesforce.com" => %{
        name: "Salesforce",
        description: "Enterprise CRM and business platform",
        type: :primary,
        market_segment: :enterprise_crm,
        spf_mechanisms: [
          "include:_spf.salesforce.com",
          "include:_spf.exacttarget.com",
          "include:_spf.pardot.com"
        ],
        common_records: [
          "v=spf1 include:_spf.salesforce.com -all"
        ]
      },

      # HubSpot
      "hubspot.com" => %{
        name: "HubSpot",
        description: "Inbound marketing and CRM platform",
        type: :primary,
        market_segment: :marketing_crm,
        spf_mechanisms: [
          "include:hubspot.net",
          "include:_spf.hubspot.com",
          "include:mail.hubspot.com"
        ],
        common_records: [
          "v=spf1 include:hubspot.net -all"
        ]
      },

      # Dynamics 365
      "dynamics.com" => %{
        name: "Microsoft Dynamics 365",
        description: "Microsoft's enterprise CRM solution",
        type: :primary,
        market_segment: :enterprise_crm,
        spf_mechanisms: [
          "include:spf.protection.outlook.com",
          "include:dynamics.com"
        ],
        common_records: [
          "v=spf1 include:spf.protection.outlook.com -all"
        ]
      },

      # Zendesk
      "zendesk.com" => %{
        name: "Zendesk",
        description: "Customer service and engagement platform",
        type: :primary,
        market_segment: :customer_support,
        spf_mechanisms: [
          "include:mail.zendesk.com",
          "include:_spf.zendesk.com"
        ],
        common_records: [
          "v=spf1 include:mail.zendesk.com -all"
        ]
      },

      # Freshworks
      "freshworks.com" => %{
        name: "Freshworks",
        description: "Customer engagement software suite",
        type: :primary,
        market_segment: :business_crm,
        spf_mechanisms: [
          "include:freshworks.com",
          "include:spf.freshworks.com"
        ],
        common_records: [
          "v=spf1 include:freshworks.com -all"
        ]
      },

      # Zoho CRM
      "zohocrm.com" => %{
        name: "Zoho CRM",
        description: "Zoho's CRM platform",
        type: :primary,
        market_segment: :business_crm,
        spf_mechanisms: [
          "include:zoho.com",
          "include:zohocrm.com"
        ],
        common_records: [
          "v=spf1 include:zoho.com -all"
        ]
      },

      # Pipedrive
      "pipedrive.com" => %{
        name: "Pipedrive",
        description: "Sales CRM and pipeline management",
        type: :primary,
        market_segment: :sales_crm,
        spf_mechanisms: [
          "include:pipedrive.com",
          "include:mail.pipedrive.com"
        ],
        common_records: [
          "v=spf1 include:pipedrive.com -all"
        ]
      }
    }
  end
end
