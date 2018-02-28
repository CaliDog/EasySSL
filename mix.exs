defmodule EasySSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :easy_ssl,
      version: "1.0.0",
      elixir: "~> 1.6",
      description: "SSL/X509 parsing for humans.",
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: ["coveralls": :test, "coveralls.detail": :test, "coveralls.post": :test, "coveralls.html": :test]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:excoveralls, "~> 0.8", only: :test}
    ]
  end
end
