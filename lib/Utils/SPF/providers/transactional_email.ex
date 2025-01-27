defmodule DomainTwistex.SPF.Providers.TransactionalEmail do

  @moduledoc """
  Defines transactional email provider domains commonly found in SPF records.
  """

  def providers do
    %{
      # SendGrid
      "sendgrid.net" => %{
        name: "SendGrid",
        description: "Twilio's email delivery platform",
        type: :primary,
        market_segment: :transactional,
        spf_mechanisms: [
          "include:sendgrid.net",
          "include:sendgrid.com"
        ],
        common_records: [
          "v=spf1 include:sendgrid.net -all"
        ]
      },

      # Mailgun
      "mailgun.org" => %{
        name: "Mailgun",
        description: "Transactional email API service",
        type: :primary,
        market_segment: :transactional,
        spf_mechanisms: [
          "include:mailgun.org",
          "include:spf.mailgun.org"
        ],
        common_records: [
          "v=spf1 include:mailgun.org -all"
        ]
      },

      # Amazon SES
      "amazonses.com" => %{
        name: "Amazon SES",
        description: "Amazon Simple Email Service",
        type: :primary,
        market_segment: :transactional,
        spf_mechanisms: [
          "include:amazonses.com",
          "ip4:199.255.192.0/22",
          "ip4:199.127.232.0/22"
        ],
        common_records: [
          "v=spf1 include:amazonses.com -all"
        ]
      },

      # Postmark
      "postmarkapp.com" => %{
        name: "Postmark",
        description: "Transactional email delivery service",
        type: :primary,
        market_segment: :transactional,
        spf_mechanisms: [
          "include:spf.mtasv.net",
          "include:postmarkapp.com"
        ],
        common_records: [
          "v=spf1 include:spf.mtasv.net -all"
        ]
      },

      # Mandrill/Mailchimp
      "mandrillapp.com" => %{
        name: "Mandrill",
        description: "Mailchimp's transactional email service",
        type: :primary,
        market_segment: :transactional,
        spf_mechanisms: [
          "include:spf.mandrillapp.com",
          "include:spf.mailchimp.com"
        ],
        common_records: [
          "v=spf1 include:spf.mandrillapp.com -all"
        ]
      },

      # SparkPost
      "sparkpostmail.com" => %{
        name: "SparkPost",
        description: "Enterprise email delivery service",
        type: :primary,
        market_segment: :transactional,
        spf_mechanisms: [
          "include:sparkpostmail.com",
          "include:spf.sparkpostmail.com"
        ],
        common_records: [
          "v=spf1 include:sparkpostmail.com -all"
        ]
      }
    }
  end
end
