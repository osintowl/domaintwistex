defmodule DomainTwistex.MixProject do
  use Mix.Project

  def project do
    [
      app: :domaintwistex,
      version: "0.5.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Domain twisting library using twistrs",
      package: package(),
      rustler: [
        crates: [
          domaintwistex: [
            path: "native/domaintwistex",
            mode: if(Mix.env() == :prod, do: :release, else: :debug)
          ]
        ]
      ]
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
      {:rustler, "~> 0.36.0"},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "domaintwistex",
      licenses: ["BSD-3-Clause"],
      links: %{"GitHub" => "https://github.com/nix2intel/domaintwistex"},
      files: ~w(lib native/domaintwistex/src native/domaintwistex/Cargo.* 
      native/domaintwistex/.cargo README.md mix.exs)
    ]
  end
end
