package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/maramilod/SadeemTech-Task/models"
	"github.com/maramilod/SadeemTech-Task/storage"
	"github.com/maramilod/SadeemTech-Task/user_handlers" // Assuming this is where user_handlers.go is located
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	config := &storage.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Password: os.Getenv("DB_PASS"),
		User:     os.Getenv("DB_USER"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
		DBName:   os.Getenv("DB_NAME"),
	}

	db, err := storage.NewConnection(config)
	if err != nil {
		log.Fatal("could not load the database")
	}

	err = models.MigrateUsers(db)
	if err != nil {
		log.Fatal("could not migrate db")
	}

	repo := user_handlers.NewRepository(db)
	app := fiber.New()
	repo.SetupRoutes(app)
	app.Listen(":8080")
}
