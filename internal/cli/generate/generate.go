package generate

import (
	"log/slog"
	"os"
	"sync"
	"time"

	"hathr-backend/internal/cli/hathr"
	"hathr-backend/internal/env"

	"github.com/google/uuid"
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

	// Generate playlists
	next := uuid.Nil
	for {
		env.Logger.Info("Fetching users", slog.String("next", next.String()))
		users, err := hathr.ListUsers(bearerToken, next, 100, env)
		if err != nil {
			fatal(env, "Failed to list users", slog.Any("error", err))
		}
		if len(users.IDs) == 0 {
			env.Logger.Info("No more users to process")
			break
		}

		env.Logger.Info("Processing users", slog.Int("count", len(users.IDs)), slog.String("next", users.Next.String()))
		var wg sync.WaitGroup
		wg.Add(len(users.IDs))
		for _, userID := range users.IDs {
			go func() {
				defer wg.Done()
				var err error
				if playlistType == "weekly" {
					err = hathr.CreateWeeklyPlaylist(currentTime, userID, bearerToken, env)
				} else {
					err = hathr.CreateMonthlyPlaylist(currentTime, userID, bearerToken, env)
				}

				if err != nil {
					env.Logger.Error("Failed to create playlist", slog.String("user_id", userID.String()), slog.Any("error", err))
				}
			}()
		}
		wg.Wait()
		next = users.Next
		env.Logger.Info("All users in batch processed", slog.String("next", users.Next.String()))
	}

	env.Logger.Info("All users processed")
}
