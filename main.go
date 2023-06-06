package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var (
	clientID     = os.Getenv("AZURE_OAUTH2_CLIENT_ID")
	clientSecret = os.Getenv("AZURE_OAUTH2_CLIENT_SECRET")
	redirectURL  = "http://localhost:8080/auth/callback"
	scopes       = []string{"openid", "profile", "email"}
	endpoint     = microsoft.AzureADEndpoint(os.Getenv("AZURE_OAUTH2_TENANT_ID"))
)

func getConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}
}

func getAuthURL() string {
	config := getConfig()
	authURL := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	return authURL
}

func handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	// Exchange authorization code for token
	token, err := getConfig().Exchange(r.Context(), code)
	if err != nil {
		// Handle error
		fmt.Printf("Token exchange error: %s", err.Error())
		return
	}

	// fmt.Println(token.AccessToken)
	// fmt.Println(token.Extra("id_token"))
	groups, err := getGroups(token.AccessToken)
	if err != nil {
		// Handle error
		fmt.Printf("Error fetching groups: %s", err.Error())
		return
	}

	// Process the groups data
	fmt.Println(string(groups))
	w.Write(groups)
}

func getGroups(accessToken string) ([]byte, error) {
	url := "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func main() {
	http.HandleFunc("/auth/callback", handleAuthCallback)
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, getAuthURL(), http.StatusFound)
	})

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
