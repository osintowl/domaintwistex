defmodule DomainTwistex.SPF.Providers.EmailWorkspaces do

  @moduledoc """
  Defines email workspace provider domains commonly found in SPF records.
  Focuses on business email and collaboration platforms.
  """

  def providers do
    %{
      "oraclecloud.com" => %{
        name: "Oracle Cloud",
        description: "Oracle cloud infrastructure and services",
        type: :primary,
        market_segment: :cloud,
        spf_mechanisms: [
          "include:spf_c.oraclecloud.com",
          "include:spf_s.oraclecloud.com",
          "include:spf_s1.oraclecloud.com",
          "include:rp.oracleemaildelivery.com"
        ],
        common_records: [
          "v=spf1 include:spf_c.oraclecloud.com -all"
        ]
      },

      "amazonses.com" => %{
        name: "Amazon SES",
        description: "Amazon Simple Email Service",
        type: :primary,
        market_segment: :cloud_email,
        spf_mechanisms: [
          "include:amazonses.com",
          "include:email-smtp.*.amazonaws.com"
        ],
        common_records: [
          "v=spf1 include:amazonses.com -all"
        ]
      },

      "google.com" => %{
        name: "Google Workspace",
        description: "Google cloud email and collaboration platform",
        type: :primary,
        market_segment: :cloud_email,
        spf_mechanisms: [
          "include:_spf.google.com",
          "include:googlemail.com"
        ],
        common_records: [
          "v=spf1 include:_spf.google.com -all"
        ]
      },

      "firebasemail.com" => %{
        name: "Firebase",
        description: "Google Firebase cloud platform",
        type: :primary,
        market_segment: :cloud,
        spf_mechanisms: [
          "include:_spf.firebasemail.com"
        ],
        common_records: [
          "v=spf1 include:_spf.firebasemail.com -all"
        ]
      }, 
      # Microsoft 365 (formerly Office 365)
      "microsoft.com" => %{
        name: "Microsoft 365",
        description: "Microsoft's cloud email and productivity suite",
        type: :primary,
        market_segment: :enterprise,
        spf_mechanisms: [
          "include:spf.protection.outlook.com",
          "include:spf-a.outlook.com",
          "include:spf-b.outlook.com",
          "include:tenant-name.mail.protection.outlook.com"
        ],
        common_records: [
          "v=spf1 include:spf.protection.outlook.com -all"
        ]
      },

      # IBM Notes/Domino (formerly Lotus Notes)
      "ibm.com" => %{
        name: "IBM Notes/Domino",
        description: "IBM's enterprise collaboration platform",
        type: :primary,
        market_segment: :enterprise,
        spf_mechanisms: [
          "include:spf.notes.na.collabserv.com",
          "include:spf.notes.ce.collabserv.com",
          "include:spf.notes.ap.collabserv.com"
        ],
        common_records: [
          "v=spf1 include:spf.notes.na.collabserv.com -all"
        ]
      },
      "outlook.com" => %{
        name: "Microsoft 365",
        description: "Microsoft's enterprise email and collaboration platform",
        type: :primary,
        market_segment: :enterprise,
        spf_mechanisms: [
          "include:spf.protection.outlook.com",
          "include:outlook.com"
        ],
        common_records: [
          "v=spf1 include:spf.protection.outlook.com -all"
        ]
      },

      # Also add the protection subdomain explicitly
      "protection.outlook.com" => %{
        name: "Microsoft 365",
        description: "Microsoft's enterprise email and collaboration platform",
        type: :primary,
        market_segment: :enterprise,
        spf_mechanisms: [
          "include:spf.protection.outlook.com"
        ],
        common_records: [
          "v=spf1 include:spf.protection.outlook.com -all"
        ]
      },

      # Zoho Workplace
      "zoho.com" => %{
        name: "Zoho Workplace",
        description: "Zoho's integrated workspace platform",
        type: :primary,
        market_segment: :business,
        spf_mechanisms: [
          "include:zoho.com",
          "include:spf.zoho.com",
          "include:zohomail.com"
        ],
        common_records: [
          "v=spf1 include:zoho.com -all"
        ]
      },

      # Rackspace Email
      "emailsrvr.com" => %{
        name: "Rackspace Email",
        description: "Rackspace's business email hosting",
        type: :primary,
        market_segment: :business,
        spf_mechanisms: [
          "include:emailsrvr.com",
          "include:spf.emailsrvr.com",
          "include:secure.emailsrvr.com"
        ],
        common_records: [
          "v=spf1 include:emailsrvr.com -all"
        ]
      },

      # FastMail
      "fastmail.com" => %{
        name: "FastMail",
        description: "Professional email hosting service",
        type: :primary,
        market_segment: :business,
        spf_mechanisms: [
          "include:spf.fastmail.com",
          "include:spf1.fastmail.com",
          "include:spf2.fastmail.com"
        ],
        common_records: [
          "v=spf1 include:spf.fastmail.com -all"
        ]
      },

      # Namecheap Email Hosting
      "namecheap.com" => %{
        name: "Namecheap Email Hosting",
        description: "Namecheap's professional email hosting service",
        type: :primary,
        market_segment: :business,
        spf_mechanisms: [
          "include:spf.namecheap.com",
          "include:mail.namecheap.com"
        ],
        common_records: [
          "v=spf1 include:spf.namecheap.com -all"
        ]
      },

      # GoDaddy Workspace Email
      "godaddy.com" => %{
        name: "GoDaddy Workspace Email",
        description: "GoDaddy's professional email hosting",
        type: :primary,
        market_segment: :business,
        spf_mechanisms: [
          "include:spf.secureserver.net",
          "include:mailspf.secureserver.net"
        ],
        common_records: [
          "v=spf1 include:secureserver.net -all"
        ]
      },

      # OVH Email Pro
      "ovh.com" => %{
        name: "OVH Email Pro",
        description: "OVH's professional email hosting",
        type: :primary,
        market_segment: :business,
        spf_mechanisms: [
          "include:mx.ovh.com",
          "include:spf.mail.ovh.net"
        ],
        common_records: [
          "v=spf1 include:mx.ovh.com -all"
        ]
      },

      # iCloud Mail
      "icloud.com" => %{
        name: "iCloud Mail",
        description: "Apple's email service",
        type: :primary,
        market_segment: :consumer,
        spf_mechanisms: [
          "include:icloud.com",
          "include:spf.mail.icloud.com"
        ],
        common_records: [
          "v=spf1 include:icloud.com -all"
        ]
      },

      # ProtonMail
      "protonmail.com" => %{
        name: "ProtonMail",
        description: "Secure email service",
        type: :primary,
        market_segment: :security_focused,
        spf_mechanisms: [
          "include:spf.protonmail.ch",
          "include:mail.protonmail.ch"
        ],
        common_records: [
          "v=spf1 include:spf.protonmail.ch -all"
        ]
      }
    }
  end
end
