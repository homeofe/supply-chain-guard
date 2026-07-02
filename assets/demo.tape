# VHS tape for the README demo GIF (https://github.com/charmbracelet/vhs)
#
# Rendered by .github/workflows/demo.yml (manual workflow_dispatch), which
# builds the CLI from the current checkout, copies the malicious test fixture
# to ./suspicious-package, runs this tape, and uploads assets/demo.gif as an
# artifact. The GIF is then committed via the normal gated release flow -
# never bot-pushed (the AAHP handoff gate would reject it).
#
# Local render (needs vhs + ttyd + ffmpeg):
#   npm run build && npm link
#   cp -r src/__tests__/fixtures/malicious-npm-pkg ./suspicious-package
#   vhs assets/demo.tape

Output assets/demo.gif

Set FontSize 14
Set Width 1000
Set Height 700
Set Padding 12
Set Theme "Dracula"
Set TypingSpeed 45ms

Type "supply-chain-guard scan ./suspicious-package"
Sleep 800ms
Enter
Sleep 7s
