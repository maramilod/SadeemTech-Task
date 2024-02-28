package storage

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"regexp"
	"log"
	"net/http"
	"os"
	"strconv" // Import strconv for converting int to string
	"time"   // Import time for token expiration
	"github.com/maramilod/SadeemTech-Task/models"
	"github.com/maramilod/SadeemTech-Task/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"path/filepath"
)

type Config struct {
	Host     string
	Port     string
	Password string
	User     string
	DBName   string
	SSLMode  string
}

func NewConnection(config *Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return db, err
	}
	return db, nil
}


// Email validation regex pattern
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func (r *Repository) CreateUser(context *fiber.Ctx) error {
	user := User{}

	err := context.BodyParser(&user)

	if err != nil {
		context.Status(http.StatusUnprocessableEntity).JSON(
			&fiber.Map{"message": "request failed"})
		return err
	}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			context.Status(http.StatusInternalServerError).JSON(
				&fiber.Map{"message": "could not hash password"})
			return err
		}
		user.Password = string(hashedPassword)

	// Validate the image file extension
	if !isValidImageExtension(user.Image) {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "invalid image file extension, only .jpg and .png are allowed"})
		return fmt.Errorf("invalid image file extension")
	}

	// Validate the email format
	if !isValidEmail(user.Email) {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "invalid email format"})
		return fmt.Errorf("invalid email format")
	}

	err = r.DB.Create(&user).Error
	if err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "could not create user"})
		return err
	}

	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "user has been added"})
	return nil
}

// isValidImageExtension checks if the given file extension is .jpg or .png
func isValidImageExtension(filename string) bool {
	extension := strings.ToLower(filepath.Ext(filename))
	return extension == ".jpg" || extension == ".png"
}


func (r *Repository) DeleteUser(context *fiber.Ctx) error {
	userModel := models.Users{}
	id := context.Params("id")
	if id == "" {
		context.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"message": "id cannot be empty",
		})
		return nil
	}

	err := r.DB.Delete(userModel, id)

	if err.Error != nil {
		context.Status(http.StatusBadRequest).JSON(&fiber.Map{
			"message": "could not delete user",
		})
		return err.Error
	}
	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "user delete successfully",
	})
	return nil
}

func (r *Repository) GetUsers(context *fiber.Ctx) error {
	userModels := &[]models.Users{}

	err := r.DB.Find(userModels).Error
	if err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "could not get users"})
		return err
	}

	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "users fetched successfully",
		"data":    userModels,
	})
	return nil
}

func (r *Repository) GetUserByID(context *fiber.Ctx) error {

	id := context.Params("id")
	userModel := &models.Users{}
	if id == "" {
		context.Status(http.StatusInternalServerError).JSON(&fiber.Map{
			"message": "id cannot be empty",
		})
		return nil
	}

	fmt.Println("the ID is", id)

	err := r.DB.Where("id = ?", id).First(userModel).Error
	if err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "could not get the user"})
		return err
	}
	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "user id fetched successfully",
		"data":    userModel,
	})
	return nil
}


func (r *Repository) SetupRoutescrud(apps *fiber.App) {
	api := apps.Group("/login")
	api.Post("/create_users", r.CreateUser)
	api.Delete("delete_user/:id", r.DeleteUser)
	api.Get("/get_users/:id", r.GetUserByID)
	api.Get("/users", r.GetUsers)
}




// login start
func (r *Repository) LoginUser(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	// Assuming you have a way to access the database connection
	// For example, you might have a global Repository variable or pass it as a parameter
	user := models.Users{}

	// Replace `database.DB` with the correct way to access your database connection
	// For example, if you have a global Repository variable named `repo`, use `repo.DB`
	r.DB.Where("email = ?", data["email"]).First(&user)

	if user.ID ==  0 {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "user not found",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(data["password"])); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "incorrect password",
		})
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.ID)),
		ExpiresAt: time.Now().Add(time.Hour *  24).Unix(), //1 day
	})

	token, err := claims.SignedString(SecretKey)

	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": "could not login",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour *  24),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	apps := fiber.New()
	r.SetupRoutescrud(apps)
	apps.Listen(":8080")


	return c.JSON(fiber.Map{
		"message": "success",
	})
}