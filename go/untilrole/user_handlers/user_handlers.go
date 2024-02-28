package user_handlers

import (
	"regexp"
	"net/http"
	"fmt"
	"strconv"
	"time"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/maramilod/SadeemTech-Task/models"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"path/filepath"

)

// Email validation regex pattern
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}


var SecretKey = []byte("your_secret_key")

type User struct {
	Name		string `json:"name"`
	Image		string `json:"image"`
	Email		string `json:"email"`
	Password	string `json:"password"`
	Role		string `json:"role"`
}

type Repository struct {
	DB *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{DB: db}
}




func (r *Repository) SetupRoutes(app *fiber.App) {
    api := app.Group("/api")
    api.Post("/login", r.LoginUser)
    api.Get("/users", JWTAuthMiddleware, r.GetUsers)
	api.Post("/logout", r.LogoutUser) 
	api.Post("/Register", r.Register) 
}




// login start
func (r *Repository) LoginUser(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}
	user := models.Users{}

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

	token, err := claims.SignedString([]byte(SecretKey))

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


	return c.JSON(fiber.Map{
		"message": "success",
	})
}

//login end

func JWTAuthMiddleware(c *fiber.Ctx) error {
    token := c.Cookies("jwt")
    fmt.Println("Token:", token) // Debugging line
    if token == "" {
        return c.Status(fiber.StatusUnauthorized).SendString("No token provided")
    }

    claims, err := validateToken(token)
 

	c.Locals("claims", claims)
	   if err != nil {
        fmt.Println("Token validation error:", err) // Debugging line
        return c.Status(fiber.StatusUnauthorized).SendString("Invalid token")
    }
    return c.Next()
}



func validateToken(token string) (jwt.Claims, error) {
    tokenClaims, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
        return SecretKey, nil
    })

    if err != nil {
        return nil, err
    }

    if !tokenClaims.Valid {
        return nil, errors.New("token is invalid")
    }

    return tokenClaims.Claims, nil
}




func (r *Repository) GetUsers(context *fiber.Ctx) error {
    claims, ok := context.Locals("claims").(jwt.Claims)
    if !ok {
        return context.Status(fiber.StatusInternalServerError).SendString("Failed to retrieve claims")
    }

    // Correctly extract the userID from the claims
    userID, err := strconv.Atoi(claims.(*jwt.StandardClaims).Issuer)
    if err != nil {
        return context.Status(fiber.StatusInternalServerError).SendString("Invalid user ID in token")
    }

    user := models.Users{}
    err = r.DB.Where("id = ?", userID).First(&user).Error
    if err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return context.Status(fiber.StatusNotFound).SendString("User not found")
        }
        return context.Status(fiber.StatusInternalServerError).SendString("Database error")
    }

    // Check if the user role is "Admin"
    if *user.Role == "admin" {
        userModels := &[]models.Users{}

        err := r.DB.Find(userModels).Error
        if err != nil {
            return context.Status(http.StatusBadRequest).JSON(
                &fiber.Map{"message": "could not get users"})
        }

        return context.Status(http.StatusOK).JSON(&fiber.Map{
            "message": "users fetched successfully",
            "data":    userModels,
        })
    } else {
        // If the user is not an admin, return a message
        return context.Status(http.StatusOK).JSON(&fiber.Map{
            "message": *user.Role,
        })
    }
}

// Register start


func (r *Repository) Register(context *fiber.Ctx) error {
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
//re

func (r *Repository) LogoutUser(c *fiber.Ctx) error {
    // Clear the JWT token cookie
    c.Cookie(&fiber.Cookie{
        Name:     "jwt",
        Value:    "",
        Expires:  time.Now().Add(-time.Hour), // Set to expire in the past
        HTTPOnly: true,
    })

    // Return a success message
    return c.JSON(fiber.Map{
        "message": "Successfully logged out",
    })
}
