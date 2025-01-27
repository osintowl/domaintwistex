defmodule DomainTwistex.SPF.Providers.SecurityProviders do
  @moduledoc """
  Defines email security provider domains commonly found in SPF records.
  Focuses on email security gateways, filters, security awareness platforms,
  and other security services that send or relay email.
  """

  def category do
    %{
      name: "Email Security Providers",
      description: "Email security and filtering infrastructure",
      providers: providers()
    }
  end

  def providers do
    %{
      "knowbe4.com" => %{
        name: "KnowBe4",
        description: "Security awareness training platform",
        type: :security_training,
        spf_mechanisms: [
          "include:spf.knowbe4.com",
          "include:_spf.knowbe4.com"
        ],
        common_records: [
          "v=spf1 include:spf.knowbe4.com -all"
        ]
      },
      "cisco.com" => %{
        name: "Cisco Security",
        description: "Cisco email security and protection services",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:%{d}.ff.spf-protect.dmp.cisco.com",
          "include:%{d}.ce.spf-protect.dmp.cisco.com",
          "include:%{d}.b0.spf-protect.dmp.cisco.com",
          "include:%{d}.5c.spf-protect.dmp.cisco.com",
          "include:res.cisco.com"
        ],
        common_records: [
          "v=spf1 include:%{d}.ff.spf-protect.dmp.cisco.com -all",
          "v=spf1 include:res.cisco.com -all"
        ]
      },

      "cofense.com" => %{
        name: "Cofense",
        description: "Phishing awareness and defense platform",
        type: :security_training,
        spf_mechanisms: [
          "include:spf.cofense.com",
          # Legacy domain
          "include:_spf.phishme.com"
        ],
        common_records: [
          "v=spf1 include:spf.cofense.com -all"
        ]
      },
      "infosecinstitute.com" => %{
        name: "Infosec IQ",
        description: "Security awareness training platform",
        type: :security_training,
        spf_mechanisms: [
          "include:spf.infosecinstitute.com"
        ],
        common_records: [
          "v=spf1 include:spf.infosecinstitute.com -all"
        ]
      },

      "barracudanetworks.com" => %{
        name: "Barracuda",
        description: "Email protection and security platform",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:*.ess.barracudanetworks.com"
        ],
        common_records: [
          "v=spf1 include:*.ess.barracudanetworks.com -all"
        ]
      },

      "agari.com" => %{
        name: "Agari",
        description: "Email security and anti-phishing platform",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:*.spf-protect.agari.com",
          "include:*.spf-protect.agari-dns.net"
        ],
        common_records: [
          "v=spf1 include:*.spf-protect.agari.com -all"
        ]
      },

      "securence.com" => %{
        name: "Securence",
        description: "Email security and archiving solution",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:spf.securence.com"
        ],
        common_records: [
          "v=spf1 include:spf.securence.com -all"
        ]
      },

      "fireeyecloud.com" => %{
        name: "FireEye",
        description: "Cyber security and malware protection",
        type: :primary,
        market_segment: :security,
        spf_mechanisms: [
          "include:_spf.fireeyecloud.com",
          "include:_spf.fireeyegov.com"
        ],
        common_records: [
          "v=spf1 include:_spf.fireeyecloud.com -all"
        ]
      },

      "ondmarc.com" => %{
        name: "OnDMARC",
        description: "DMARC email security platform",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:_spf.smart.ondmarc.com"
        ],
        common_records: [
          "v=spf1 include:_spf.smart.ondmarc.com -all"
        ]
      },
      
      "vali.email" => %{
        name: "Valimail",
        description: "Email authentication and security platform",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email"
        ],
        common_records: [
          "v=spf1 include:_spf.vali.email -all"
        ]
      },

      "mailcontrol.com" => %{
        name: "Mail Control",
        description: "Email security and control platform",
        type: :primary,
        market_segment: :email_security,
        spf_mechanisms: [
          "include:mailcontrol.com"
        ],
        common_records: [
          "v=spf1 include:mailcontrol.com -all"
        ]
      },
      # Email Security Gateways
      "ironport.com" => %{
        name: "Cisco IronPort",
        description: "Cisco email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:spf.ironport.com",
          "include:cisco-cloud-esa.com",
          "include:esa.cisco.com"
        ],
        common_records: [
          "v=spf1 include:spf.ironport.com -all",
          "v=spf1 include:cisco-cloud-esa.com -all"
        ]
      },
      "barracuda.com" => %{
        name: "Barracuda",
        description: "Barracuda email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:spf.barracuda.com",
          "include:barracudanetworks.com",
          "include:barracudacentral.org"
        ],
        common_records: [
          "v=spf1 include:spf.barracuda.com -all"
        ]
      },
      "pphosted.com" => %{
        name: "Proofpoint",
        description: "Proofpoint email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:pphosted.com",
          "include:emaildefense.proofpoint.com",
          # For O365 integration
          "include:spf.protection.outlook.com"
        ],
        common_records: [
          "v=spf1 include:pphosted.com -all"
        ]
      },
      "mimecast.com" => %{
        name: "Mimecast",
        description: "Mimecast email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:_netblocks.mimecast.com",
          "include:_netblocks2.mimecast.com",
          "include:_netblocks3.mimecast.com"
        ],
        common_records: [
          "v=spf1 include:_netblocks.mimecast.com include:_netblocks2.mimecast.com include:_netblocks3.mimecast.com -all"
        ]
      },
      "forcepoint.com" => %{
        name: "Forcepoint",
        description: "Forcepoint email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:spf.forcepoint.com",
          "include:emailprotection.forcepoint.com"
        ],
        common_records: [
          "v=spf1 include:spf.forcepoint.com -all"
        ]
      },
      "trendmicro.com" => %{
        name: "Trend Micro",
        description: "Trend Micro email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:spf.trendmicro.com",
          "include:cloud.trendmicro.com"
        ],
        common_records: [
          "v=spf1 include:spf.trendmicro.com -all"
        ]
      },
      "sophos.com" => %{
        name: "Sophos",
        description: "Sophos email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:spf.sophos.com",
          # Acquired service
          "include:reflexion.net"
        ],
        common_records: [
          "v=spf1 include:spf.sophos.com -all"
        ]
      },
      "zscaler.com" => %{
        name: "Zscaler",
        description: "Zscaler email security infrastructure",
        type: :email_security,
        spf_mechanisms: [
          "include:spf.zscaler.com",
          "include:zscalerthree.net"
        ],
        common_records: [
          "v=spf1 include:spf.zscaler.com -all"
        ]
      },

      # Advanced Threat Protection
      "fireeye.com" => %{
        name: "FireEye/Mandiant",
        description: "FireEye email security infrastructure",
        type: :advanced_security,
        spf_mechanisms: [
          "include:spf.fireeye.com",
          "include:emailprotection.fireeye.com"
        ],
        common_records: [
          "v=spf1 include:spf.fireeye.com -all"
        ]
      },
      "checkpoint.com" => %{
        name: "Check Point",
        description: "Check Point email security infrastructure",
        type: :advanced_security,
        spf_mechanisms: [
          "include:spf.checkpoint.com",
          "include:mail.checkpoint.com"
        ],
        common_records: [
          "v=spf1 include:spf.checkpoint.com -all"
        ]
      },

      # DMARC/SPF Management
      "dmarcian.com" => %{
        name: "dmarcian",
        description: "DMARC management platform",
        type: :email_authentication,
        spf_mechanisms: [
          "include:spf.dmarcian.com"
        ],
        common_records: [
          "v=spf1 include:spf.dmarcian.com -all"
        ]
      },
      "valimail.com" => %{
        name: "Valimail",
        description: "Email authentication platform",
        type: :email_authentication,
        spf_mechanisms: [
          "include:spf.valimail.com"
        ],
        common_records: [
          "v=spf1 include:spf.valimail.com -all"
        ]
      }
    }
  end
end
