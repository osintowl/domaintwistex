defmodule DomainTwistex.MixProject do
  use Mix.Project

  @version "1.0.0"
  @source_url "https://github.com/osintowl/domaintwistex"

  def project do
    [
      app: :domaintwistex,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "DomainTwistex",
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl, :public_key]
    ]
  end

  defp deps do
    [
      {:req, "~> 0.5 or ~> 0.6 or ~> 0.7"},
      {:jason, "~> 1.4"},
      {:ex_doc, "~> 0.39", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Pure Elixir domain permutation and typosquatting detection engine.
    Generates 18 permutation types, resolves concurrently with DNS/WHOIS
    enrichment, SPF analysis, and fuzzy matching for suspicious domain detection.
    """
  end

  defp package do
    [
      name: "domaintwistex",
      licenses: ["BSD-3-Clause"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      files: ~w(
        lib
        priv
        mix.exs
        README.md
        LICENSE
        CHANGELOG.md
      )
    ]
  end

  defp docs do
    [
      main: "DomainTwistex",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"],
      groups_for_modules: [
        "Core": [
          DomainTwistex,
          DomainTwistex.Twist,
          DomainTwistex.Permutate,
          DomainTwistex.ResolverError
        ],
        "DNS & Network": [
          DomainTwistex.DNS,
          DomainTwistex.HTTP,
          DomainTwistex.Whois,
          DomainTwistex.Utils
        ],
        "Domain Names": [
          DomainTwistex.Domain,
          DomainTwistex.IDNA
        ],
        "SPF Analysis": [
          DomainTwistex.SPF,
          DomainTwistex.SPF.ProviderCategories
        ]
      ]
    ]
  end
end
