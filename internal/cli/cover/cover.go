package cover

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
	// Load time zone
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

	env.Logger.Info("Generating playlist cover", slog.String("playlist_type", playlistType))
	if playlistType == "weekly" {
		prevWeek := currentTime.AddDate(0, 0, -7)
		err = hathr.CreateWeeklyPlaylistCover(uint8(prevWeek.Day()), prevWeek.Month(), uint16(prevWeek.Year()), bearerToken, env)
	} else {
		prevMonth := currentTime.AddDate(0, -1, 0)
		err = hathr.CreateMonthlyPlaylistCover(prevMonth.Month(), uint16(prevMonth.Year()), bearerToken, env)
	}
	if err != nil {
		fatal(env, "Failed to generate playlist cover", slog.Any("error", err))
	}

	// Generate playlist cover
	env.Logger.Info("Successfully created playlist cover")
}
