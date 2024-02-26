package routes

import (
    "github.com/gofiber/fiber/v2"
    "github.com/maramilod/SadeemTech-Task/go/go-auth/controller"
)

func Setup(app *fiber.App) {
    app.Get("/", controller.Hello)
}
