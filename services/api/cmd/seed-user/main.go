package main

import (
	"context"
	"flag"
	"log"
	"path/filepath"

	"pvn-v2/services/api/internal/config"
	"pvn-v2/services/api/internal/db"
)

func main() {
	email := flag.String("email", "", "user email")
	password := flag.String("password", "", "user password")
	role := flag.String("role", "user", "user role")
	flag.Parse()
	if *email == "" || *password == "" {
		log.Fatal("-email and -password are required")
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	store, err := db.Open(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(filepath.Join("migrations", "001_init.sql")); err != nil {
		if err := store.Migrate(filepath.Join("..", "..", "migrations", "001_init.sql")); err != nil {
			log.Fatal(err)
		}
	}
	if err := store.UpsertUser(context.Background(), *email, *password, *role); err != nil {
		log.Fatal(err)
	}
	log.Printf("seeded user %s", *email)
}
