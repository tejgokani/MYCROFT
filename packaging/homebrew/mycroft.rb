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
      sha256 "3cd5b278c847dd9abfb832e10a3b2a844ea639cc94cabfbce2ab412fbb16aba8"
    end
    on_intel do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-x86_64-apple-darwin.tar.gz"
      sha256 "948a716b0625d24152131fe785df50352c95153658fe6fea0c51d10571de141e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0db6263703da4d180b41f43e6868b05b42c54ee334dd4b3833c5418a7e85fc08"
    end
    on_intel do
      url "https://github.com/tejgokani/MYCROFT/releases/download/v#{version}/mycroft-x86_64-unknown-linux-musl.tar.gz"
      sha256 "f93e35de45b908f38eabb428b80d5061b72214e80c925b0b5bdc164265882357"
    end
  end

  def install
    bin.install "mycroft"
  end

  test do
    assert_match "mycroft", shell_output("#{bin}/mycroft --version")
  end
end
