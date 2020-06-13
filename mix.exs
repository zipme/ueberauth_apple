defmodule UeberauthApple.Mixfile do
  use Mix.Project

  @version "0.1.0"
  @url "https://github.com/loopsocial/ueberauth_apple"

  def project do
    [
      app: :ueberauth_apple,
      version: @version,
      name: "Ueberauth Apple Strategy",
      package: package(),
      elixir: "~> 1.6",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      source_url: @url,
      homepage_url: @url,
      description: description(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [applications: [:logger, :oauth2, :ueberauth, :jose]]
  end

  defp deps do
    [
      {:oauth2, ">= 0.8.0"},
      {:ueberauth, "~> 0.4"},
      {:jose, "~> 1.0"},
      {:httpoison, "~> 1.0"}
    ]
  end

  defp docs do
    [extras: ["README.md", "CONTRIBUTING.md"]]
  end

  defp description do
    "An Uberauth strategy for Apple authentication."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Jerry Luk"],
      licenses: ["MIT"],
      links: %{GitHub: @url}
    ]
  end
end
