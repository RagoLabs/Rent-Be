package main

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"slices"

	db "github.com/Hopertz/rent/db/sqlc"
	"github.com/Hopertz/rent/pkg/mail"
	"github.com/labstack/echo/v4"
)

type SignupData struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

type ResetCompleteData struct {
	Email string `json:"email"`
}

func (app *application) registerAdminHandler(c echo.Context) error {

	var input struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, envelope{"error": err.Error()})
	}

	if err := app.validator.Struct(input); err != nil {
		return c.JSON(http.StatusBadRequest, envelope{"error": err.Error()})
	}

	emails := strings.Split(app.config.emails, ",")

	found := slices.Contains(emails, input.Email)

	if !found {
		return c.JSON(http.StatusUnauthorized, envelope{"error": "email not allowed"})
	}

	pwd, err := db.SetPassword(input.Password)

	if err != nil {
		slog.Error("error generating hash password", "error", err)
		return err
	}

	args := db.CreateAdminParams{
		Email:        input.Email,
		PasswordHash: pwd.Hash,
		Activated:    false,
	}

	a, err := app.store.CreateAdmin(c.Request().Context(), args)

	if err != nil {
		switch {

		case err.Error() == db.DuplicateEmail:
			return c.JSON(http.StatusBadRequest, envelope{"error": "email is already in use"})

		default:
			slog.Error("error creating admin", "error", err)
			return c.JSON(http.StatusInternalServerError, envelope{"error": "internal server error"})
		}

	}

	expiry := time.Now().Add(3 * 24 * time.Hour)

	token, err := app.store.NewToken(a.ID, expiry, db.ScopeActivation)
	if err != nil {
		slog.Error("error generating new token", "error", err)
		return c.JSON(http.StatusInternalServerError, envelope{"error": "internal server error"})
	}

	app.background(func() {

		dt := mail.MailerData{
			Email: args.Email,
			Token: token.Plaintext,
			Url:   app.config.frontend_url,
		}

		if err := app.mailer.SendMail("welcome_template", dt); err != nil {
			slog.Error("error sending welcome email to user", "error", err, "email", args.Email)
		}
	})

	return c.JSON(http.StatusCreated, nil)
}

func (app *application) activateAdminHandler(c echo.Context) error {

	var input struct {
		TokenPlaintext string `json:"token" validate:"required,len=26"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, envelope{"error": err.Error()})
	}

	if err := app.validator.Struct(input); err != nil {
		return c.JSON(http.StatusBadRequest, envelope{"error": err.Error()})
	}

	tokenHash := sha256.Sum256([]byte(input.TokenPlaintext))

	args := db.GetHashTokenForAdminParams{
		Scope:  db.ScopeActivation,
		Hash:   tokenHash[:],
		Expiry: time.Now(),
	}

	admin, err := app.store.GetHashTokenForAdmin(c.Request().Context(), args)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			slog.Error("error fetching token user admin", "error", err)
			return c.JSON(http.StatusNotFound, envelope{"error": "invalid token or expired"})
		default:
			slog.Error("error fetching token user admin", "error", err)
			return c.JSON(http.StatusInternalServerError, envelope{"error": "internal server error"})
		}

	}

	if admin.Activated {
		return c.JSON(http.StatusBadRequest, envelope{"error": "admin arleady actvated"})
	}

	param := db.UpdateAdminParams{

		ID:           admin.ID,
		Email:        admin.Email,
		Activated:    true,
		PasswordHash: admin.PasswordHash,
		Version:      admin.Version,
	}
	_, err = app.store.UpdateAdmin(c.Request().Context(), param)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			slog.Error("error conflict updating admin ", "error", err)
			return c.JSON(http.StatusConflict, envelope{"error": "unable to complete request due to an edit conflict"})
		default:
			slog.Error("error updating admin ", "error", err)
			return c.JSON(http.StatusInternalServerError, envelope{"error": "internal server error"})
		}

	}

	return c.JSON(http.StatusOK, nil)
}

func (app *application) updateAdminPasswordOnResetHandler(c echo.Context) error {

	var input struct {
		Password       string `json:"password" validate:"required,min=8"`
		TokenPlaintext string `json:"token" validate:"required,len=26"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, envelope{"error": err.Error()})
	}

	if err := app.validator.Struct(input); err != nil {
		return c.JSON(http.StatusBadRequest, envelope{"error": err.Error()})
	}

	tokenHash := sha256.Sum256([]byte(input.TokenPlaintext))

	args := db.GetHashTokenForAdminParams{
		Scope:  db.ScopePasswordReset,
		Hash:   tokenHash[:],
		Expiry: time.Now(),
	}

	admin, err := app.store.GetHashTokenForAdmin(c.Request().Context(), args)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			slog.Error("error fetching token user admin", "error", err)
			return c.JSON(http.StatusNotFound, envelope{"errors": "invalid token"})
		default:
			slog.Error("error fetching token user admin", "error", err)
			return c.JSON(http.StatusInternalServerError, envelope{"error": "internal server error"})
		}
	}

	pwd, err := db.SetPassword(input.Password)

	if err != nil {
		return err
	}

	_, err = app.store.UpdateAdmin(c.Request().Context(), db.UpdateAdminParams{
		Email:        admin.Email,
		PasswordHash: pwd.Hash,
		Activated:    true,
		ID:           admin.ID,
		Version:      admin.Version,
	})

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return c.JSON(http.StatusConflict, envelope{"error": "unable to complete request due to an edit conflict"})
		default:
			slog.Error("error updating admin ", "error", err)
			return c.JSON(http.StatusInternalServerError, envelope{"error": "internal server error"})
		}
	}

	d := db.DeleteAllTokenParams{
		Scope: db.ScopePasswordReset,
		ID:    admin.ID,
	}
	err = app.store.DeleteAllToken(c.Request().Context(), d)

	if err != nil {
		slog.Error("error deleting reset password token for user admin", "error", err)
	}

	app.background(func() {

		args := mail.MailerData{
			Email: admin.Email,
			Url:   app.config.frontend_url,
		}

		if err := app.mailer.SendMail("completedreset_template", args); err != nil {
			slog.Error("error sending welcome email to user", "error", err, "email", args.Email)
		}
	})

	return c.JSON(http.StatusOK, nil)
}
