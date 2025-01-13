# Cobra-OAuth2

Go module that simplifies the integration of OAuth2 authorization flow and token storage into a [Cobra CLI](https://github.com/spf13/cobra). This library provides prebuilt commands for handling login and token management, making it easy to integrate secure authentication into your CLI applications.

---

## Features

- **Quick Setup**: Add OAuth2 support to your Cobra CLI with just a few lines of code.
- **Token Management**: Automatically handle token storage and retrieval.
- **Flexible Storage Providers**: Store tokens securely using your preferred storage backend (e.g., keyring, file system).
- **Prebuilt Commands**: Includes `login` and `token` commands to handle authentication flows out of the box.

---

## Installation

Install the module via `go get`:

```sh
go get github.com/nauthera/cobra-oauth2
```

---

## Example Usage

### 1. Main Application Setup

Define your main entry point and execute your Cobra CLI:

```go
package main

import "github.com/nauthera/cobra-oauth2/examples/basic/cmd"

func main() {
	cmd.Execute()
}
```

### 2. Root Command Setup

Set up the root command and initialize OAuth2 commands:

```go
package cmd

import (
	"net/url"
	"os"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
	"github.com/spf13/cobra"
)

const CLIENT_ID = "my-client-id"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "cobra-oauth2",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	discoveryUrl, err := url.Parse("https://foo-bar.nauthera.io/.well-known/openid-configuration")
	if err != nil {
		rootCmd.PrintErr("error parsing discovery URL: ", err)
		return
	}

	storageProvider := storage.NewKeyringStorage(CLIENT_ID)

	options := []auth.Option{
		auth.WithDiscoveryURL(*discoveryUrl),
		auth.WithClientID(CLIENT_ID),
		auth.WithStorageProvider(storageProvider),
	}

	rootCmd.AddCommand(
		auth.NewLoginCommand(options...),
		auth.NewTokenCommand(options...),
	)
}
```

### Commands

- **`login`**: Initiates the OAuth2 login flow.
- **`token`**: Fetches and displays the current access token.

---

## Key Components

### 1. **Authorization Options**

Options can be customized using `auth.Option` functions:

- `auth.WithDiscoveryURL(url.URL)`: Specify the OAuth2 discovery URL.
- `auth.WithClientID(string)`: Set the client ID for the OAuth2 flow.
- `auth.WithStorageProvider(auth.StorageProvider)`: Define where tokens are stored.

### 2. **Storage Providers**

The library supports secure token storage via pluggable providers, including:

- **Keyring Storage**: Use `storage.NewKeyringStorage(clientID)` for secure, system-native storage.
- **File-Based Storage**: Implement your own storage backend if needed.

---

## Benefits

- **Secure by Default**: Tokens are securely stored using modern practices.
- **Flexible Customization**: Easily extend and adapt to your specific use case.
- **Minimal Code**: Focus on your application's logic without worrying about OAuth2 complexity.

---

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to help improve the library.

---

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
