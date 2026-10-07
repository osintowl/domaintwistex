defmodule DomainTwistex.ResolverError do
  @moduledoc """
  Raised before a scan starts when the configured DNS resolvers don't answer.
  """

  defexception [:reason, :nameservers]

  @impl true
  def message(%{reason: reason, nameservers: nameservers}) do
    resolvers = if nameservers in [nil, []], do: "system resolver", else: inspect(nameservers)

    "DNS preflight failed against #{resolvers}: #{inspect(reason)}. " <>
      "Check connectivity, or pass explicit resolvers, e.g. nameservers: [\"1.1.1.1\", \"8.8.8.8\"] " <>
      "(CLI: -n 1.1.1.1 -n 8.8.8.8)"
  end
end
