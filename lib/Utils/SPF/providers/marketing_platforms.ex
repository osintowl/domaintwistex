# lib/ex_spf_parser/providers/marketing_platforms.ex
defmodule DomainTwistex.SPF.Providers.MarketingPlatforms do
  @moduledoc """
  Defines email marketing, automation, and customer engagement platforms including
  newsletter services, marketing automation tools, and campaign management systems.
  """

  def category do
    %{
      name: "Marketing & Automation Platforms",
      description: "Email marketing, automation, and customer engagement solutions",
      providers: providers()
    }
  end

  def providers do
    %{
      "sendgrid.net" => %{
        name: "SendGrid",
        description: "Email delivery and marketing platform",
        type: :primary,
        market_segment: :email_marketing,
        spf_mechanisms: ["include:sendgrid.net"],
        common_records: ["v=spf1 include:sendgrid.net -all"]
      },

    "mcsv.net" => %{
        name: "Mailchimp",
        description: "Email marketing and automation platform",
        type: :primary,
        market_segment: :email_marketing,
        spf_mechanisms: [
          "include:servers.mcsv.net",
          "include:spf.mandrillapp.com"
        ],
        common_records: ["v=spf1 include:servers.mcsv.net -all"]
      },

      "constantcontact.com" => %{
        name: "Constant Contact",
        description: "Email marketing and automation service",
        type: :primary,
        market_segment: :email_marketing,
        spf_mechanisms: ["include:spf.constantcontact.com"],
        common_records: ["v=spf1 include:spf.constantcontact.com -all"]
      },

      "createsend.com" => %{
        name: "Campaign Monitor",
        description: "Email marketing and automation platform",
        type: :primary,
        market_segment: :email_marketing,
        spf_mechanisms: ["include:_spf.createsend.com"],
        common_records: ["v=spf1 include:_spf.createsend.com -all"]
      },

      "sendinblue.com" => %{
        name: "Sendinblue",
        description: "Digital marketing and email platform",
        type: :primary,
        market_segment: :email_marketing,
        spf_mechanisms: ["include:spf.sendinblue.com"],
        common_records: ["v=spf1 include:spf.sendinblue.com -all"]
      },

      # Marketing Automation
      "exacttarget.com" => %{
        name: "Salesforce Marketing Cloud",
        description: "Enterprise marketing automation platform",
        type: :primary,
        market_segment: :marketing_automation,
        spf_mechanisms: ["include:cust-spf.exacttarget.com"],
        common_records: ["v=spf1 include:cust-spf.exacttarget.com -all"]
      },

      "hubspotemail.net" => %{
        name: "HubSpot",
        description: "Marketing, sales, and CRM platform",
        type: :primary,
        market_segment: :marketing_automation,
        spf_mechanisms: [
          "include:*.spf*.hubspotemail.net"
        ],
        common_records: ["v=spf1 include:*.spf*.hubspotemail.net -all"]
      },

      "mktomail.com" => %{
        name: "Marketo",
        description: "Marketing automation software",
        type: :primary,
        market_segment: :marketing_automation,
        spf_mechanisms: ["include:mktomail.com"],
        common_records: ["v=spf1 include:mktomail.com -all"]
      },

      "pardot.com" => %{
        name: "Pardot",
        description: "B2B marketing automation by Salesforce",
        type: :primary,
        market_segment: :marketing_automation,
        spf_mechanisms: ["include:et._spf.pardot.com"],
        common_records: ["v=spf1 include:et._spf.pardot.com -all"]
      },

      "act-on.net" => %{
        name: "Act-On",
        description: "Marketing automation platform",
        type: :primary,
        market_segment: :marketing_automation,
        spf_mechanisms: [
          "include:_spf.act-on.net",
          "include:_netblocks.act-on.net"
        ],
        common_records: ["v=spf1 include:_spf.act-on.net -all"]
      },

      "messagegears.net" => %{
        name: "MessageGears",
        description: "Enterprise email marketing platform",
        type: :primary,
        market_segment: :email_marketing,
        spf_mechanisms: ["include:_spf.messagegears.net"],
        common_records: ["v=spf1 include:_spf.messagegears.net -all"]
      },

      # Marketo
      "marketo.com" => %{
        name: "Adobe Marketo Engage",
        description: "B2B marketing automation platform",
        website: "marketo.com",
        type: :marketing_automation,
        features: [
          "Email Marketing",
          "Lead Management",
          "Account-Based Marketing",
          "Marketing Analytics",
          "Revenue Attribution"
        ],
        additional_domains: [
          "mktdns.com",
          "mktomail.com"
        ],
        sending_limits: %{
          monthly_limit: "Enterprise-grade",
          hourly_rate: "Customizable"
        },
        market_segment: :enterprise,
        certification_types: ["SOC 2", "ISO 27001"],
        parent_company: "Adobe",
        specializations: ["B2B Marketing"]
      },


      # Campaign Monitor
      "campaignmonitor.com" => %{
        name: "Campaign Monitor",
        description: "Email marketing for agencies and businesses",
        website: "campaignmonitor.com",
        type: :email_marketing,
        features: [
          "Email Marketing",
          "Automation",
          "Personalization",
          "Analytics",
          "Agency Features"
        ],
        additional_domains: [
          "createsend.com",
          "cmail19.com"
        ],
        sending_limits: %{
          monthly_limit: "Based on plan",
          hourly_rate: "Unlimited on high-tier plans"
        },
        market_segment: [:agency, :smb],
        certification_types: ["SOC 2"],
        specializations: ["Agency", "Creative Teams"]
      },

      # ActiveCampaign
      "activecampaign.com" => %{
        name: "ActiveCampaign",
        description: "Customer experience automation platform",
        website: "activecampaign.com",
        type: :marketing_automation,
        features: [
          "Email Marketing",
          "Marketing Automation",
          "CRM",
          "Machine Learning",
          "Site Tracking"
        ],
        additional_domains: [
          "activehosted.com"
        ],
        sending_limits: %{
          monthly_limit: "Based on contact count",
          hourly_rate: "Unlimited on higher plans"
        },
        market_segment: [:smb, :enterprise],
        certification_types: ["SOC 2", "ISO 27001"],
        specializations: ["eCommerce", "B2B"]
      },

      # Klaviyo
      "klaviyo.com" => %{
        name: "Klaviyo",
        description: "eCommerce marketing automation platform",
        website: "klaviyo.com",
        type: :marketing_automation,
        features: [
          "Email Marketing",
          "SMS Marketing",
          "eCommerce Integration",
          "Predictive Analytics",
          "Customer Segmentation"
        ],
        sending_limits: %{
          monthly_limit: "Based on plan",
          hourly_rate: "Dynamic"
        },
        market_segment: [:smb, :enterprise],
        certification_types: ["SOC 2"],
        specializations: ["eCommerce"],
        integrations: ["Shopify", "WooCommerce", "Magento"]
      },

      # Braze
      "braze.com" => %{
        name: "Braze",
        description: "Customer engagement platform",
        website: "braze.com",
        type: :customer_engagement,
        features: [
          "Email Marketing",
          "Push Notifications",
          "SMS",
          "In-App Messages",
          "Cross-Channel Orchestration"
        ],
        additional_domains: [
          "braze.eu"
        ],
        sending_limits: %{
          monthly_limit: "Enterprise-grade",
          hourly_rate: "Customizable"
        },
        market_segment: :enterprise,
        certification_types: ["SOC 2", "ISO 27001"],
        specializations: ["Mobile", "Cross-Channel"]
      }
    }
  end

  @doc """
  Returns providers by specific marketing feature
  """
  def providers_by_feature(feature) do
    providers()
    |> Enum.filter(fn {_domain, data} ->
      feature in data.features
    end)
    |> Map.new()
  end

  @doc """
  Returns providers by market segment
  """
  def providers_by_segment(segment) do
    providers()
    |> Enum.filter(fn {_domain, data} ->
      case data.market_segment do
        segments when is_list(segments) -> segment in segments
        single_segment -> single_segment == segment
      end
    end)
    |> Map.new()
  end
end
