package release

import (
	"log/slog"
	"os"
	"time"

	"hathr-backend/internal/cli/hathr"
	"hathr-backend/internal/env"

	"github.com/spf13/cobra"
)

func fatal(env *env.Env, msg string, args ...any) {
	env.Logger.Error(msg, args...)
	os.Exit(1)
}

func Run(cmd *cobra.Command, _ []string, env *env.Env) {
	env.Logger.Debug("Loading timezone America/New_York")
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		fatal(env, "Failed to load timezone", slog.String("error", err.Error()))
	}

	currentTime := time.Now().In(loc)
	currentTime = time.Date(currentTime.Year(), currentTime.Month(), currentTime.Day(), currentTime.Hour(), currentTime.Minute(), 0, 0, loc) // Round to the minute
	playlistType, err := cmd.Flags().GetString("playlist-type")
	if err != nil {
		fatal(env, "Failed to get playlist type flag", slog.String("error", err.Error()))
	}

	// Validate arguments
	env.Logger.Debug("Validating arguments")
	if playlistType != "weekly" && playlistType != "monthly" {
		fatal(env, "Invalid playlist type", slog.String("playlist_type", playlistType))
	}

	// Login to Hathr
	env.Logger.Info("Logging in to Hathr")
	bearerToken, err := hathr.AdminLogin(env)
	if err != nil {
		fatal(env, "Failed to login to Hathr backend", slog.Any("error", err))
	}

	env.Logger.Info("Releasing playlist", slog.String("playlist_type", playlistType), slog.String("year", currentTime.Format("2006")), slog.String("month", currentTime.Month().String()), slog.String("day", currentTime.Format("02")))
	if playlistType == "monthly" {
		err = hathr.ReleaseMonthlyPlaylist(currentTime, bearerToken, env)
	} else {
		err = hathr.ReleaseWeeklyPlaylist(currentTime, bearerToken, env)
	}

	if err != nil {
		fatal(env, "Failed to release playlist", slog.Any("error", err))
	}

	env.Logger.Info("Successfully released playlist", slog.String("playlist_type", playlistType), slog.String("year", currentTime.Format("2006")), slog.String("month", currentTime.Month().String()), slog.String("day", currentTime.Format("02")))
}
