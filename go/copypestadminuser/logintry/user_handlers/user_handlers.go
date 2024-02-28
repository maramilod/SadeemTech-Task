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
	api.Post("/register", JWTAuthMiddleware, r.Register) 
	api.Delete("deleteUser/:id", JWTAuthMiddleware, r.DeleteUser)
	api.Put("updateUser/:id", JWTAuthMiddleware, r.UpdateUser)
	api.Get("/search/:email", JWTAuthMiddleware, r.Search)
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
        ExpiresAt: time.Now().Add(time.Hour *  24).Unix(), //  1 day
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

	var message string
	if *user.Role == "admin" {
		message = `As an admin, you can use these methods:
	- Get /users to show all users accounts
	- Post /logout to remove the cookie and invalidate the JWT Token
	- Post /register to create a new user account
	- Delete /deleteUser/:id to delete a specific user by its ID
	- Put /updateUser/:id to update information of a specific user by its ID
	- Get /search/:email to search for a user by their email address.`
	} else {
		message = `As a worker, you can use these methods: <br/>
	- Get /users to show all your data <br/>
	- Post /logout to remove the cookie and invalidate the JWT Token <br/>
	- Delete /deleteUser/0 to delete your account and logout <br/>
	- Put /updateUser/0 to update information of your account.`
	}
	
	return c.JSON(fiber.Map{
		"message": message,
	})
}

//login end

func JWTAuthMiddleware(c *fiber.Ctx) error {
    token := c.Cookies("jwt")
    fmt.Println("Token:", token) // Debugging line
    if token == "" {
        return c.Status(fiber.StatusUnauthorized).SendString("you have to login first ^-^")
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

func (r *Repository) UserAdmin(context *fiber.Ctx) (*models.Users, error) {
    claims, ok := context.Locals("claims").(jwt.Claims)
    if !ok {
        return nil, fmt.Errorf("failed to retrieve claims")
    }

    userID, err := strconv.Atoi(claims.(*jwt.StandardClaims).Issuer)
    if err != nil {
        return nil, fmt.Errorf("invalid user ID in token: %w", err)
    }

    user := models.Users{}
    err = r.DB.Where("id = ?", userID).First(&user).Error
    if err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, fmt.Errorf("user not found")
        }
        return nil, fmt.Errorf("database error: %w", err)
    }

    return &user, nil
}


func (r *Repository) UpdateUser(c *fiber.Ctx) error {


	useradmin, err := r.UserAdmin(c)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

   
    userID := c.Params("id")

    var user models.Users
    if err := c.BodyParser(&user); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Cannot parse JSON",
        })
    }

    if userID == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "User ID is missing",
        })
    }

    id, err := strconv.Atoi(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid user ID",
        })
    }

    existingUser := models.Users{}
    if err := r.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
        return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "email already exists"})
    }

    if user.Password != nil {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
        if err != nil {
            return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"message": "could not hash password"})
        }
        *user.Password = string(hashedPassword)
    }

    if user.Image != nil && !isValidImageExtension(*user.Image) {
        return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "invalid image file extension, only .jpg and .png are allowed"})
    }

    if user.Email != nil && !isValidEmail(*user.Email) {
        return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "invalid email format"})
    }
	if useradmin != nil && *useradmin.Role == "admin" {
    result := r.DB.Model(&models.Users{}).Where("id = ?", id).Updates(user)
    if result.Error != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to update user",
        })
    }
	if result.RowsAffected ==  0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "User not found",
        })
    }

    return c.Status(fiber.StatusOK).JSON(fiber.Map{
        "message": "User updated successfully",
    })
	 } else {
		result := r.DB.Model(&models.Users{}).Where("id = ?", useradmin.ID).Updates(user)
    if result.Error != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to update your account",
        })
    }
    if result.RowsAffected ==  0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "data not found",
        })
    }

    return c.Status(fiber.StatusOK).JSON(fiber.Map{
        "message": "your account updated successfully",
    })
	}


}





func (r *Repository) DeleteUser(context *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(context)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {
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
}else {
	erro := r.LogoutUser(context)
    if erro != nil {
        // Handle error appropriately
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to logout user"})
    }
	userModel := models.Users{}
err := r.DB.Delete(userModel, useradmin.ID)

if err.Error != nil {
	context.Status(http.StatusBadRequest).JSON(&fiber.Map{
		"message": "could not your account",
	})
	return err.Error
}
	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "you deleted your account and loged out successfully",
	})
	return nil
}}

func (r *Repository) GetUsers(context *fiber.Ctx) error {
    user, err := r.UserAdmin(context)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    // Assuming you want to fetch all users if the user is an admin
    if user != nil && *user.Role == "admin" {
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
        // If the user is not an admin, return a message or handle accordingly
        return context.Status(http.StatusOK).JSON(&fiber.Map{
            "message": "you can only see your data",
			"data":    user,
        })
    }
	
}

func (r *Repository) Search(context *fiber.Ctx) error {
    user, err := r.UserAdmin(context)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    // Assuming you want to fetch all users if the user is an admin
    if user != nil && *user.Role == "admin" {
        email := context.Params("email") // Assuming you pass the email as a URL parameter named "email"
        if email == "" {
            context.Status(http.StatusBadRequest).JSON(&fiber.Map{
                "message": "email cannot be empty",
            })
            return nil
        }

        fmt.Println("the email is", email)

        userModel := &models.Users{}
        err := r.DB.Where("email = ?", email).First(userModel).Error
        if err != nil {
            if errors.Is(err, gorm.ErrRecordNotFound) {
                context.Status(http.StatusNotFound).JSON(
                    &fiber.Map{"message": "user not found"})
            } else {
                context.Status(http.StatusInternalServerError).JSON(
                    &fiber.Map{"message": "database error"})
            }
            return err
        }

        context.Status(http.StatusOK).JSON(&fiber.Map{
            "message": "user fetched successfully",
            "data":    userModel,
        })
        return nil
    }

    context.Status(http.StatusForbidden).JSON(&fiber.Map{
        "message": "sorry, you can't use this method. You need to be an admin",
    })
    return nil
}

// Register start


func (r *Repository) Register(context *fiber.Ctx) error {

	useradmin, err := r.UserAdmin(context)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {


	user := User{}

	err := context.BodyParser(&user)

	if err != nil {
		context.Status(http.StatusUnprocessableEntity).JSON(
			&fiber.Map{"message": "request failed"})
		return err
	}

	  // Check if the email already exists
    existingUser := models.Users{}
    if err := r.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
        // Email already exists
        return context.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "email already exists"})
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
	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "sorry u can't use this method you need to be admin"})
	return nil

}

// isValidImageExtension checks if the given file extension is .jpg or .png
func isValidImageExtension(filename string) bool {
	extension := strings.ToLower(filepath.Ext(filename))
	return extension == ".jpg" || extension == ".png"
}




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
