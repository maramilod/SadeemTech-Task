package main

import (
	"maramilod/Golang/database"
	"maramilod/Golang/routes"
	"github.com/gofiber/fiber"
)

func main() {
	database.Connect()

	app := fiber.New()

	routes.Setup(app)

	app.Listen(":8000")
}
