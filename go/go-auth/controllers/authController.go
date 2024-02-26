package controller

import "github.com/gofiber/fiber"

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello, World!")
}