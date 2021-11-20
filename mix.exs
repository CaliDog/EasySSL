defmodule EasySSL.MixProject do
  use Mix.Project

  @source_url "https://github.com/CaliDog/EasySSL"
  @version "1.3.0"

  def project do
    [
      app: :easy_ssl,
      name: "EasySSL",
      version: @version,
      elixir: "~> 1.6",
      deps: deps(),
      docs: docs(),
      package: package(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:excoveralls, "~> 0.8", only: :test},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:poison, "~> 2.0", only: :test}
    ]
  end

  defp package() do
    [
      name: "easy_ssl",
      description: "SSL/X509 parsing for humans.",
      files: ["lib", "mix.exs", "README.md", "LICENSE.md"],
      maintainers: ["Ryan Sears"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      extras: [
        "LICENSE.md": [title: "License"],
        "README.md": [title: "Overview"]
      ],
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"]
    ]
  end
end
