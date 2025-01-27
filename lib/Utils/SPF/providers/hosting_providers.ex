defmodule DomainTwistex.SPF.Providers.HostingProviders do

  @moduledoc """
  Defines hosting provider domains commonly found in SPF records.
  """

  def providers do
    %{
           "secureserver.net" => %{
        name: "GoDaddy",
        description: "Domain registrar and web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:secureserver.net",
          "include:spf.secureserver.net",
          "include:mailspf.secureserver.net"
        ],
        common_records: [
          "v=spf1 include:secureserver.net -all"
        ]
      },

      "websitewelcome.com" => %{
        name: "HostGator",
        description: "Web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:websitewelcome.com"
        ],
        common_records: [
          "v=spf1 include:websitewelcome.com -all"
        ]
      },

      "kinstamailservice.com" => %{
        name: "Kinsta Mail",
        description: "Managed WordPress hosting provider's email service",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:relay.kinstamailservice.com"
        ],
        common_records: [
          "v=spf1 include:relay.kinstamailservice.com -all"
        ]
      },

      "site4now.net" => %{
        name: "Site4Now",
        description: "Web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:_spf.site4now.net"
        ],
        common_records: [
          "v=spf1 include:_spf.site4now.net -all"
        ]
      },

      "a2hosting.com" => %{
        name: "A2 Hosting",
        description: "Web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:spf.a2hosting.com"
        ],
        common_records: [
          "v=spf1 include:spf.a2hosting.com -all"
        ]
      },

      "aruba.it" => %{
        name: "Aruba",
        description: "Italian web hosting and cloud provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:_spf.aruba.it"
        ],
        common_records: [
          "v=spf1 include:_spf.aruba.it -all"
        ]
      },

      "hostwhitelabel.com" => %{
        name: "Host White Label",
        description: "White label hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:spf.hostwhitelabel.com"
        ],
        common_records: [
          "v=spf1 include:spf.hostwhitelabel.com -all"
        ]
      },

      

      # Plesk
      "plesk.com" => %{
        name: "Plesk",
        description: "Web hosting platform and control panel",
        type: :infrastructure,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:plesk.com",
          "include:spf.plesk.com"
        ],
        common_records: [
          "v=spf1 include:spf.plesk.com -all"
        ]
      },


      # Bluehost
      "bluehost.com" => %{
        name: "Bluehost",
        description: "Web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:bluehost.com",
          "include:spf.bluehost.com"
        ],
        common_records: [
          "v=spf1 include:spf.bluehost.com -all"
        ]
      },

      # SiteGround
      "siteground.com" => %{
        name: "SiteGround",
        description: "Web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:siteground.com",
          "include:spf.siteground.com"
        ],
        common_records: [
          "v=spf1 include:spf.siteground.com -all"
        ]
      },

      # DreamHost
      "dreamhost.com" => %{
        name: "DreamHost",
        description: "Web hosting provider",
        type: :primary,
        market_segment: :hosting,
        spf_mechanisms: [
          "include:dreamhost.com",
          "include:spf.dreamhost.com"
        ],
        common_records: [
          "v=spf1 include:spf.dreamhost.com -all"
        ]
      },

      # DigitalOcean
      "digitalocean.com" => %{
        name: "DigitalOcean",
        description: "Cloud infrastructure provider",
        type: :infrastructure,
        market_segment: :cloud,
        spf_mechanisms: [
          "include:spf.digitalocean.com",
          "include:mail.digitalocean.com"
        ],
        common_records: [
          "v=spf1 include:spf.digitalocean.com -all"
        ]
      }
    }
  end
end
