package main

import (
    "log"
	"github.com/maramilod/SadeemTech-Task/go/go-auth/database"
	"github.com/maramilod/SadeemTech-Task/go/go-auth/routes"
    "github.com/gofiber/fiber/v2"
)

func main() {
database.Connect()

    app := fiber.New()

   routes.Setup(app)

    log.Fatal(app.Listen(":8000"))
}