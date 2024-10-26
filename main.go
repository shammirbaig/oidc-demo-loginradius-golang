package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

var (
	oauthConfig = &oauth2.Config{
		ClientID:     "",
		RedirectURL:  "http://localhost:5000/callback",
		ClientSecret: "",
		Scopes:       []string{"user"},
	}
	globalProvider   *oidc.Provider
	globalOuthConfig *oauth2.Config
)

func main() {
	fmt.Println("Hello, World!")

	provider, err := oidc.NewProvider(context.Background(), "https://internal-shammir.hub.loginradius.com/service/oidc/oidc-test1")
	if err != nil {
		log.Fatalf("Failed to create new provider: %v", err)
	}
	globalProvider = provider

	// Set up the OAuth2 configuration with the client ID, secret, redirect URL, and scopes.
	oauth2Config := &oauth2.Config{
		ClientID:     oauthConfig.ClientID,
		ClientSecret: oauthConfig.ClientSecret,
		RedirectURL:  oauthConfig.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	globalOuthConfig = oauth2Config

	router := gin.Default()
	router.GET("/login", func(ctx *gin.Context) {

		authURL := globalOuthConfig.AuthCodeURL("state", oidc.Nonce(""))

		http.Redirect(ctx.Writer, ctx.Request, authURL, http.StatusFound)

	})

	router.GET("/callback", func(ctx *gin.Context) {

		code := ctx.Query("code")
		oauth2Token, err := globalOuthConfig.Exchange(ctx, code)
		if err != nil {
			log.Printf("Error exchanging code for token: %v", err)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Println("Missing ID token")
			return
		}

		var verifier = globalProvider.Verifier(&oidc.Config{ClientID: globalOuthConfig.ClientID, SkipClientIDCheck: true})

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Printf("Error verifying ID token: %v", err)
			return
		}

		// Extract claims from the verified ID token.
		var claims interface{}
		if err := idToken.Claims(&claims); err != nil {
			log.Printf("Error extracting claims: %v", err)
			return
		}

		if claimsMap, ok := claims.(map[string]interface{}); ok {
			name, ok := claimsMap["name"].(string)
			if ok {
				//fmt.Println("Name:", name)
				ctx.JSON(http.StatusOK, gin.H{"message": "successful login of " + name})
			} else {
				fmt.Println("The 'name' claim is not a string")
			}
		} else {
			fmt.Println("claims is not a map[string]interface{}")
		}
	})

	log.Fatal(http.ListenAndServe(":5000", router))
}
