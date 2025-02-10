defmodule DomainTwistex.MixProject do
  use Mix.Project


  @version "0.6.1"
  @force_build? System.get_env("DOMAINTWISTEX_BUILD") in ["1", "true"]  
  def project do
    [
      app: :domaintwistex,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Domain twisting library using twistrs",
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler_precompiled, "~> 0.8"},
      {:rustler, ">= 0.35.0", optional: not @force_build?},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "domaintwistex",
      licenses: ["BSD-3-Clause"],
      links: %{"GitHub" => "https://github.com/osintowl/domaintwistex"},
        files: [
        "lib",
        "native",
        "checksum-*.exs",
        "mix.exs"
      ],
    ]
  end
end
