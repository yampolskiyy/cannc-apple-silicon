class CanncAppleSilicon < Formula
  desc "Experimental Ascend C compiler wrapper for Apple Silicon"
  homepage "https://github.com/yampolskiyy/cannc-apple-silicon"
  # Draft only: this private bundle has not been cleared for redistribution.
  url "https://github.com/yampolskiyy/cannc-apple-silicon/releases/download/v0.1.0-experimental/cannc-apple-silicon-0.1.0-experimental.tar.gz"
  sha256 "ea20969133620a34c74f0634efe15b1d145706392a52c38c9064b911420667f2"
  version "0.1.0"
  license :cannot_represent

  depends_on :macos
  depends_on arch: :arm64
  depends_on "python@3.14"

  def install
    libexec.install Dir["*"]
    (bin/"cannc").write <<~EOS
      #!/bin/sh
      export PYTHONDONTWRITEBYTECODE=1
      exec "#{Formula["python@3.14"].opt_bin}/python3.14" "#{opt_prefix}/libexec/homebrew_support.py" run "$HOME/Library/Application Support/cannc-homebrew" "$@"
    EOS
  end

  def caveats
    <<~EOS
      Experimental and unofficial; supports only the recorded BiSheng/Ascend profile.
      The environment is prepared automatically the first time you run cannc.
      Uninstalling the formula retains the user's environment, recovery key and outputs.
      If setup is interrupted, inspect its journal before retrying; it is not overwritten.
    EOS
  end

  test do
    assert_match "usage:", shell_output("#{bin}/cannc --help")
  end
end
