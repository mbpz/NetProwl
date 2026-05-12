# =============================================================================
# NetProwl Homebrew Cask Formula
# =============================================================================
# Usage:
#   brew install mbpz/tap/netprowl
#
# For official Homebrew Cask submission, create a PR to:
#   https://github.com/Homebrew/homebrew-cask/blob/master/Casks/n/netprowl.rb
# =============================================================================

class Netprowl < Cask
  version "0.1.0"
  sha256 "TODO: FILL_IN_SHA256_AFTER_BUILD"

  url "https://github.com/mbpz/NetProwl/releases/download/v#{version}/NetProwl-arm64.tar.gz"
  name "NetProwl"
  desc "Network reconnaissance tool"
  homepage "https://github.com/mbpz/NetProwl"

  depends_on macos: ">= :big_sur"

  app "NetProwl.app"

  post_install do
    # Clear quarantine xattr to bypass Gatekeeper popups
    system("xattr -rd com.apple.quarantine '#{staged_path}/NetProwl.app'")
  end

  zap trash: [
    "~/Library/Application Support/NetProwl",
    "~/Library/Preferences/com.netprowl.app.plist",
    "~/Library/Saved Application State/com.netprowl.app.savedState",
  ]
end
