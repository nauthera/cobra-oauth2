# Records demo.gif: `just demo`, or `vhs demo.tape` from the repository root.
#
# The CLI is examples/nauthera. It talks to internal/cmd/demoidp, a local
# server configured like nauthera-server that approves the device code on
# the third poll, so the recording needs no account and no browser.

Output demo.gif

Require go

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 620
Set Padding 20
Set TypingSpeed 45ms

Hide
Type "source scripts/demo-setup.sh && clear"
Enter
Sleep 8s
Show

Type "nauthera auth login --flow device --no-browser"
Sleep 500ms
Enter
Sleep 7500ms

Type "clear"
Enter
Type "nauthera auth status"
Sleep 500ms
Enter
Sleep 3s

Type "nauthera auth logout --no-browser"
Sleep 500ms
Enter
Sleep 4s

Hide
Type "demo_teardown"
Enter
