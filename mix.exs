defmodule DomainTwistex.MixProject do
  use Mix.Project

  @version "1.0.1"
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
      # Req before 0.6.1 unpacks compressed and archive bodies by default
      # (CVE-2026-49755). 0.5.3 through 0.5.18 also inject multipart headers
      # (CVE-2026-49756). 0.6 and 0.7 stay allowed so a host app can share one Req.
      {:req, "~> 0.6.1 or ~> 0.7"},
      # Finch 0.21 and older cannot select Mint >= 1.8, and Mint before
      # 1.10.2 is covered by the HTTP/1 and HTTP/2 client advisories.
      {:mint, ">= 1.10.2 and < 2.0.0"},
      # Mint 1.10.2 still allows hpax 1.0.3 (CVE-2026-58226, fixed in 1.0.4).
      {:hpax, ">= 1.0.4 and < 2.0.0"},
      {:jason, "~> 1.4"},
      {:ex_doc, "~> 0.39 or ~> 0.40", only: :dev, runtime: false}
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
