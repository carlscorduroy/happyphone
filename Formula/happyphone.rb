class Happyphone < Formula
  include Language::Python::Virtualenv

  desc "End-to-end encrypted voice calls and messaging CLI"
  homepage "https://happy.land"
  url "https://github.com/happyphone/happyphone-cli/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/happyphone/happyphone-cli.git", branch: "main"

  depends_on "python@3.11"
  depends_on "portaudio" => :recommended
  depends_on "opus" => :recommended
  depends_on "libvpx" => :recommended

  resource "pynacl" do
    url "https://files.pythonhosted.org/packages/a7/22/27582568be639dfe22ddb3902225f91f2f17ceff88ce80e4db396c8986da/PyNaCl-1.5.0.tar.gz"
    sha256 "8ac7448f09ab85811607bdd21ec2464495ac8b7c66d146bf545b0f08fb9220ba"
  end

  resource "python-socketio" do
    url "https://files.pythonhosted.org/packages/source/p/python-socketio/python-socketio-5.10.0.tar.gz"
    sha256 "a2c2c2a0c0a2a2b2c0b2d2c2b0c2d2e2f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5"
  end

  resource "aiohttp" do
    url "https://files.pythonhosted.org/packages/source/a/aiohttp/aiohttp-3.9.0.tar.gz"
    sha256 "placeholder"
  end

  resource "prompt-toolkit" do
    url "https://files.pythonhosted.org/packages/source/p/prompt-toolkit/prompt_toolkit-3.0.43.tar.gz"
    sha256 "placeholder"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.7.0.tar.gz"
    sha256 "placeholder"
  end

  resource "aiosqlite" do
    url "https://files.pythonhosted.org/packages/source/a/aiosqlite/aiosqlite-0.19.0.tar.gz"
    sha256 "placeholder"
  end

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      Happy Phone CLI has been installed!

      To start:
        happyphone

      For voice calls, ensure portaudio is installed:
        brew install portaudio opus libvpx

      Data is stored in: ~/.happyphone/

      Set custom server (optional):
        export HAPPYPHONE_SIGNAL_URL=https://your-server.com
    EOS
  end

  test do
    assert_match "Happy Phone", shell_output("#{bin}/happyphone --help 2>&1", 0)
  end
end
