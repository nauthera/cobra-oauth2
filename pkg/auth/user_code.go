package auth

import (
	"os"
	"time"

	"github.com/mdp/qrterminal"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

func Handle(cmd cobra.Command, verificationURIComplete string) {
	cmd.Println("Please follow the steps below to complete the authentication process:")
	cmd.Println()
	cmd.Println("1. A browser window will automatically open shortly.")
	cmd.Println("   If it doesn't, please ensure you have a compatible browser installed on your device.")
	cmd.Println("2. Once the browser is open, you will be presented with a QR code or a link.")
	cmd.Println("   - If the browser supports scanning QR codes, use the built-in QR code scanner to scan the code provided below:")
	cmd.Println()
	qrterminal.GenerateHalfBlock(verificationURIComplete, qrterminal.L, os.Stdout)
	cmd.Println()
	cmd.Println("   - If your browser does not support QR code scanning,")
	cmd.Println("     you can copy and paste the link provided below into the address bar of your browser:")
	cmd.Println()
	cmd.Printf("     %s\n", verificationURIComplete)
	cmd.Println()
	cmd.Println("3. After successfully scanning the QR code or navigating to the link,")
	cmd.Println("   follow the instructions provided in the browser window to complete the authentication process.")
	cmd.Println()

	// wait for 2 seconds before opening the browser
	time.Sleep(2 * time.Second)

	// open browser with verificationURIComplete if possible
	browser.OpenURL(verificationURIComplete)
}
