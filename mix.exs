defmodule EasySSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :easy_ssl,
      name: "EasySSL",
      version: "1.3.0",
      elixir: "~> 1.6",
      description: "SSL/X509 parsing for humans.",
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [coveralls: :test, "coveralls.detail": :test, "coveralls.post": :test, "coveralls.html": :test],
      source_url: "https://github.com/CaliDog/EasySSL",
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :private_key]
    ]
  end

  defp deps do
    [
      {:excoveralls, "~> 0.8", only: :test},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false},
      {:poison, "~> 2.0", only: :test},
    ]
  end

  defp package() do
    [
      name: "easy_ssl",
      # These are the default files included in the package
      files: ["lib", "mix.exs", "README.md"],
      maintainers: ["Ryan Sears"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/CaliDog/EasySSL"}
    ]
  end
end
