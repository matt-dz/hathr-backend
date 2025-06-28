package invite

import (
	"fmt"
	"log/slog"
	"os"

	"hathr-backend/internal/cli/hathr"
	"hathr-backend/internal/env"

	"github.com/spf13/cobra"
)

func fatal(env *env.Env, msg string, args ...any) {
	env.Logger.Error(msg, args...)
	os.Exit(1)
}

func Run(cmd *cobra.Command, _ []string, env *env.Env) {
	env.Logger.Info("Logging in to Hathr")
	accessToken, err := hathr.AdminLogin(env)
	if err != nil {
		fatal(env, "Failed to login to Hathr backend", "error", err)
	}

	env.Logger.Info("Creating invite link")
	res, err := hathr.CreateInviteCode(accessToken, env)
	if err != nil {
		fatal(env, "Failed to create invite code", "error", err)
	}

	env.Logger.Info("Invite link created", slog.String("code", res.Code), slog.Time("expires_at", res.ExpiresAt), slog.String("url", fmt.Sprintf("https://hathr.deguzman.cloud/invite?code=%s", res.Code)))
}
