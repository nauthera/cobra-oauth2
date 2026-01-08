package auth

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
	"github.com/spf13/cobra"
)

func NewLoginCommand(options ...Option) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with your OAuth2 provider using the device flow.",
		Long: `The "login" command initiates the OAuth2 Device Flow, allowing you to authenticate
with an OAuth2 provider. This flow is ideal for command-line tools that cannot display
a web browser for authentication. The user will be prompted to visit a URL and enter a
code to authenticate the CLI tool.
`,
		Run: func(cmd *cobra.Command, args []string) {
			authConfig, err := configure(options...)
			if err != nil {
				cmd.PrintErr("error configuring auth: ", err)
				return
			}

			var accessToken *AccessTokenResponse

			switch *authConfig.GrantType {
			case DeviceCode:
				deviceCode, err := FetchDeviceCode(cmd.Context(), *authConfig)
				if err != nil {
					cmd.PrintErr("error fetching device code: ", err)
					return
				}

				Handle(*cmd, deviceCode.VerificationURIComplete)

				accessToken, err = PollForAccessToken(
					cmd.Context(),
					*authConfig,
					deviceCode.DeviceCode,
					time.Duration(deviceCode.ExpiresIn)*time.Second,
					time.Duration(deviceCode.Interval)*time.Second,
				)
				if err != nil {
					cmd.PrintErr("error polling for access token: ", err)
					return
				}
			case ClientCredentials:
				accessToken, err = FetchClientCredentialsToken(cmd.Context(), *authConfig)
				if err != nil {
					cmd.PrintErr("error fetching access token: ", err)
					return
				}
			default:
				cmd.PrintErr("unsupported grant type: ", authConfig.GrantType)
				return
			}

			validFor := time.Duration(accessToken.ExpiresIn) * time.Second
			cmd.Println("Successfully authenticated!")
			cmd.Println("Your access token is valid for", validFor, "seconds.")

			storageProvider := storage.NewKeyringStorage(*authConfig.ClientId)
			if err := storageProvider.SetToken(jwt.Token{
				Raw: accessToken.AccessToken,
			}); err != nil {
				cmd.PrintErr("error storing access token: ", err)
				return
			}
		},
	}
}

func NewTokenCommand(options ...Option) *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			authConfig, err := configure(options...)
			if err != nil {
				cmd.PrintErr("error configuring auth: ", err)
				return
			}

			storageProvider := storage.NewKeyringStorage(*authConfig.ClientId)
			token, err := storageProvider.GetToken()
			if err != nil {
				cmd.PrintErr("error fetching token: ", err)
				os.Exit(1)
			}

			cmd.Print(token)
		}}
}

func NewLogoutCommand(options ...Option) *cobra.Command {
	return &cobra.Command{
		Use: "logout",
		Run: func(cmd *cobra.Command, args []string) {
			authConfig, err := configure(options...)
			if err != nil {
				cmd.PrintErr("error configuring auth: ", err)
				return
			}

			storageProvider := storage.NewKeyringStorage(*authConfig.ClientId)
			err = storageProvider.DeleteToken()
			if err != nil {
				cmd.PrintErr("error logging out: ", err)
				os.Exit(1)
			}

			cmd.Println("Successfully logged out.")
		},
	}
}
