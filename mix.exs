defmodule DomainTwistex.MixProject do
  use Mix.Project


  @version "0.9.0"

  def project do
    [
      app: :domaintwistex,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Pure Elixir domain permutation and typosquatting detection engine. Generates 18 permutation types, resolves concurrently with DNS/WHOIS enrichment, and filters suspicious domains.",
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:req, "~> 0.5.16"},
      {:ex_doc, "~> 0.39", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "domaintwistex",
      licenses: ["BSD-3-Clause"],
      links: %{"GitHub" => "https://github.com/osintowl/domaintwistex"},
      files: [
        "lib",
        "priv",
        "mix.exs"
      ]
    ]
  end
end
