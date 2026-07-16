# Homebrew formula for Mycroft (binary install from GitHub Releases).
#
# This is the source of truth; publish it to a tap repo so users can:
#   brew tap tejgokani/mycroft https://github.com/tejgokani/homebrew-mycroft
#   brew install mycroft
#
# Per release: bump `version` and replace each sha256 with the value from the
# corresponding `mycroft-<target>.tar.gz.sha256` asset (see docs/RELEASING.md).
class Mycroft < Formula
  desc "Terminal-native pentest engagement console: recon to report, one console"
  homepage "https://github.com/tejgokani/MYCROFT"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_aarch64-apple-darwin_SHA256"
    end
    on_intel do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_x86_64-apple-darwin_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_aarch64-unknown-linux-gnu_SHA256"
    end
    on_intel do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-x86_64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_x86_64-unknown-linux-musl_SHA256"
    end
  end

  def install
    bin.install "mycroft"
  end

  test do
    assert_match "mycroft", shell_output("#{bin}/mycroft --version")
  end
end
