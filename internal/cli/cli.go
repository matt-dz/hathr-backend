package cli

import (
	"log"
	"os"

	"hathr-backend/internal/cli/aggregate"
	"hathr-backend/internal/cli/cover"
	"hathr-backend/internal/cli/generate"
	"hathr-backend/internal/cli/invite"
	"hathr-backend/internal/cli/release"
	"hathr-backend/internal/env"
	"hathr-backend/internal/http"
	"hathr-backend/internal/logging"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hathr",
	Short: "Hathr CLI",
	Args:  cobra.OnlyValidArgs,
}

var generateCmd = &cobra.Command{
	Use:   "generate-playlist",
	Short: "Generate playlists",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.New()
		httpclient := http.New()
		httpclient.RetryMax = 5
		httpclient.Logger = logger
		env := env.New(logger, nil, httpclient)
		generate.Run(cmd, args, env)
	},
}

var releaseCmd = &cobra.Command{
	Use:   "release-playlist",
	Short: "Release playlists",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.New()
		httpclient := http.New()
		httpclient.RetryMax = 5
		httpclient.Logger = logger
		env := env.New(logger, nil, httpclient)
		release.Run(cmd, args, env)
	},
}

var aggregateCmd = &cobra.Command{
	Use:   "aggregate-plays",
	Short: "Aggregate plays from all providers",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.New()
		httpclient := http.New()
		httpclient.RetryMax = 5
		httpclient.Logger = logger
		env := env.New(logger, nil, httpclient)
		aggregate.Run(cmd, args, env)
	},
}

var coverCmd = &cobra.Command{
	Use:   "generate-cover",
	Short: "Generate playlist cover",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.New()
		httpclient := http.New()
		httpclient.RetryMax = 5
		httpclient.Logger = logger
		env := env.New(logger, nil, httpclient)
		cover.Run(cmd, args, env)
	},
}

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Invite users to Hathr",
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.New()
		httpclient := http.New()
		httpclient.RetryMax = 5
		httpclient.Logger = logger
		env := env.New(logger, nil, httpclient)
		invite.Run(cmd, args, env)
	},
}

func init() {
	generateCmd.Flags().String("playlist-type", "weekly", "playlist type to generate (weekly, monthly)")
	releaseCmd.Flags().String("playlist-type", "weekly", "playlist type to generate (weekly, monthly)")
	coverCmd.Flags().String("playlist-type", "weekly", "playlist type to generate (weekly, monthly)")
	rootCmd.AddCommand(generateCmd, releaseCmd, aggregateCmd, coverCmd, inviteCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
		os.Exit(1)
	}
}
