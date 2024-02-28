package user_handlers

import (
//  "io/ioutil"
//  "io"
//	"os"
	"regexp"
	"net/http"
	"fmt"
	"strconv"
	"time"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"path/filepath"
    "github.com/maramilod/SadeemTech-Task/models"
)

var SecretKey = []byte("your_secret_key")

// User structure without the ID column.
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
    // Create a new classification
    api.Post("/createclsf", JWTAuthMiddleware, r.InsertClassification)
    // Get all classifications
	api.Get("/getclsf", JWTAuthMiddleware, r.GetClsf)
    // Get classifications by name
	api.Get("/getclsf/:name", JWTAuthMiddleware, r.GetClsfName)
    // Delete a classification by ID
	api.Delete("/deleteclsf/:id", JWTAuthMiddleware, r.DeleteClsf)
    // Update a classification by ID
	api.Put("/updateclsf/:id", JWTAuthMiddleware, r.Updateclsf)

    // Insert a user classification
	api.Post("/insertuserclsf", JWTAuthMiddleware, r.InsertUserClassification)
    // Get all user classifications
	api.Get("/getuserclsf", JWTAuthMiddleware, r.GetAllUserClassifications)
    // Get a user classification by classification name
	api.Get("/getuserclsf/:clsf_name", JWTAuthMiddleware, r.GetUserClassificationByName)

    // User login
	api.Post("/login", r.LoginUser)
    // Get all users
    api.Get("/users", JWTAuthMiddleware, r.GetUsers)
    // User logout
	api.Post("/logout", r.LogoutUser)
    // User registration
	api.Post("/register", JWTAuthMiddleware, r.Register)
    // logout and Delete a your account 
	api.Delete("deleteAccount", JWTAuthMiddleware, r.DeleteAccount)
    // Delete a user by ID
	api.Delete("deleteUser/:id", JWTAuthMiddleware, r.DeleteUser)
    // Update a user by ID
	api.Put("updateUser/:id", JWTAuthMiddleware, r.UpdateUser)
    // Update a user account
	api.Put("updateUser", JWTAuthMiddleware, r.UpdateUserAccount)
    // Search for a user by email or name
	api.Get("/search/:em_or_na", JWTAuthMiddleware, r.Search)
}


func (r *Repository) GetUserClassificationByName(c *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(c)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {
    // Extract the classification name from the request parameters
    classificationName := c.Params("clsf_name")

    // Define a slice to hold the results
    var userClassifications []models.UserClassification

    // Perform a join between UserClassification and Classification tables
    // and filter by classification_name
    if err := r.DB.Joins("JOIN classifications ON classifications.id = user_classifications.classification_id").Where("classifications.name = ?", classificationName).Find(&userClassifications).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
                "error": "User classifications not found",
            })
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Error retrieving user classifications",
        })
    }

    // Return the user classifications as JSON
    return c.Status(fiber.StatusOK).JSON(userClassifications)
}
return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")

}


// GetAllUserClassifications retrieves all user classifications from the database.
func (r *Repository) GetAllUserClassifications(c *fiber.Ctx) error {
    useradmin, err := r.UserAdmin(c)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {
        // Define a slice to hold the results
        var userClassifications []models.UserClassification

        // Query the database to get all user classifications
        if err := r.DB.Find(&userClassifications).Error; err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "error": "Error retrieving user classifications",
            })
        }

        // Return the user classifications as JSON
        return c.Status(fiber.StatusOK).JSON(userClassifications)
    } 
	return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
}


	func (r *Repository) InsertUserClassification(c *fiber.Ctx) error {
		useradmin, err := r.UserAdmin(c)
		if err != nil {
			// Handle error, e.g., user not found, not an admin, or other database errors
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}
	
		if useradmin != nil && *useradmin.Role == "admin" {
		var userclassif models.UserClassification
		err := c.BodyParser(&userclassif)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Error parsing request body",
			})
		}
	
		// Check if the user_id exists in the Users table
		var user models.Users
		if err := r.DB.First(&user, userclassif.UserID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "User not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Error checking user",
			})
		}
	
		// Check if the classification_id exists in the Classification table
		var classification models.Classification
		if err := r.DB.First(&classification, userclassif.ClassificationID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "Classification not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Error checking classification",
			})
		}
	
        // Add the name of the classification
		userclassif.ClassificationName =  classification.Name
        // Add the username to the response
		userclassif.UserName = user.Name 
		// Insert the record into the database
		if err := r.DB.Create(&userclassif).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Error inserting record",
			})
		}

		// Return the created record as a response
		return c.Status(fiber.StatusCreated).JSON(userclassif)
}
return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
}


func (r *Repository) DeleteClsf(c *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(c)
		if err != nil {
			// Handle error, e.g., user not found, not an admin, or other database errors
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}
	
		if useradmin != nil && *useradmin.Role == "admin" {
    // Extract the ID from the URL parameter
    idStr := c.Params("id")
    id, err := strconv.Atoi(idStr)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid ID",
        })
    }

    // Use the ID to find the corresponding record in the database
    clsf := models.Classification{}
    if err := r.DB.Where("id = ?", id).First(&clsf).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
                "error": "Classification not found",
            })
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Database error",
        })
    }

    // Delete the record
    if err := r.DB.Delete(&clsf).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to delete classification",
        })
    }

    // Return success response
    return c.Status(fiber.StatusOK).JSON(fiber.Map{
        "message": "Classification deleted successfully",
    })

}
return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
}


func (r *Repository) Updateclsf(c *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(c)
		if err != nil {
			// Handle error, e.g., user not found, not an admin, or other database errors
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}
	
		if useradmin != nil && *useradmin.Role == "admin" {
    // Parse the ID from the URL
    id, err := strconv.Atoi(c.Params("id"))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid ID"})
    }

    // Create a new Classification struct to hold the updated data
    var updatedClassification models.Classification

    // Parse the request body into the Classification struct
    if err := c.BodyParser(&updatedClassification); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON"})
    }

    // Find the Classification by ID
    classification := models.Classification{}
    if err := r.DB.First(&classification, id).Error; err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Classification not found"})
    }

    // Update the Classification with the new data
    classification.Name = updatedClassification.Name
    classification.Status = updatedClassification.Status

    // Save the updated Classification back to the database
    if err := r.DB.Save(&classification).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not update classification"})
    }

    // Return the updated Classification
    return c.JSON(classification)
}
return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
}

// GetClsfName retrieves classifications by name
func (r *Repository) GetClsfName(c *fiber.Ctx) error {
    useradmin, err := r.UserAdmin(c)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {
    // Extract the name parameter from the URL
    name := c.Params("name")

    // Initialize a slice to hold the results
    var classifications []models.Classification

    // Query the database for classifications with the matching name
    result := r.DB.Where("name = ?", name).Find(&classifications)
    if result.Error != nil {
        // If there's an error, return a 500 status code with an error message
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching classifications"})
    }

    // If no classifications are found, return a 404 status code with a message
    if len(classifications) == 0 {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "No classifications found with the specified name"})
    }

    // Return the found classifications with a 200 status code
    return c.Status(fiber.StatusOK).JSON(classifications)
}
return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
}


func (r *Repository) GetClsf(c *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(c)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {
    classifications := []models.Classification{}
    if err := r.DB.Find(&classifications).Error; err != nil {
        return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to fetch classifications",
        })
    }

    return c.JSON(fiber.Map{
        "classifications": classifications,
    })} else {
        // Define a slice to hold the results
        var classifications []models.Classification

        // Query the database to get all user classifications where status is "public"
        if err := r.DB.Where("status = ?", "public").Find(&classifications).Error; err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "error": "Error retrieving public user classifications",
            })
        }

        // Return the public user classifications as JSON
        return c.Status(fiber.StatusOK).JSON(classifications)
    }
    
	
}

func (r *Repository) InsertClassification(c *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(c)
	if err != nil {
		// Handle error, e.g., user not found, not an admin, or other database errors
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}

	if useradmin != nil && *useradmin.Role == "admin" {
    // Parse the request body into a Classification struct
    var classification models.Classification
    if err := c.BodyParser(&classification); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot parse JSON", "message": err.Error()})
    }

    // Insert the new Classification into the database
    result := r.DB.Create(&classification)
    if result.Error != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error inserting classification you dont have to insert the id", "message": result.Error.Error()})
    }

    // Return the newly created Classification
    return c.Status(fiber.StatusCreated).JSON(classification)
}
return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
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
        ExpiresAt: time.Now().Add(time.Hour *  24).Unix(), // 1 day
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
    - Post /createclsf to Create a new classification
    - Get getclsf Get all classifications
    - Delete /deleteclsf/:id Delete a classification by ID
    - Put /updateclsf/:id Update a classification by ID
    
    - Post /insertuserclsf Insert a user classification
    - Get /getuserclsf Get all user classifications
    - Get /getuserclsf/:clsf_name Get a user classification by classification name
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
	- Delete /deleteAccount to delete your account and logout <br/>
	- Put /updateUser to update information of your account
    - Get /getuserclsf Get all public user classifications.`
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



// isValidImageExtension checks if the given file extension is .jpg or .png
func isValidImageExtension(filename string) bool {
	extension := strings.ToLower(filepath.Ext(filename))
	return extension == ".jpg" || extension == ".png"
}


// Email validation regex pattern
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
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

func (r *Repository) UpdateUserAccount(c *fiber.Ctx) error {
    user, err := r.UserAdmin(c)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    // Assuming the request body now contains an ID field to identify the user to update
    var userdata struct {
        ID       uint   `json:"id"`
        Password *string `json:"password"`
        Image    *string `json:"image"`
        Email    *string `json:"email"`
    }

    if err := c.BodyParser(&userdata); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Cannot parse JSON",
        })
    }

    // Find the existing user by ID
    existingUser := models.Users{}
    if err := r.DB.First(&existingUser, user.ID).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
    }

    // Check and hash the password if it's not nil
    if userdata.Password != nil && *userdata.Password != "" {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*userdata.Password), bcrypt.DefaultCost)
        if err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Could not hash password"})
        }
        *existingUser.Password = string(hashedPassword)
    }

    // Only validate and update the image if it's not nil
    if userdata.Image != nil && *userdata.Image != "" {
        if !isValidImageExtension(*userdata.Image) {
            return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid image file extension, only .jpg and .png are allowed"})
        }
        // Handle image file upload here
        // For example, save the uploaded file to a permanent location and update the existingUser.Image field with the new file path
    }

    // Validate the email format
    if userdata.Email != nil && *userdata.Email != "" && !isValidEmail(*userdata.Email) {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid email format"})
    }

    // Exclude the role field from being updated
    result := r.DB.Model(&existingUser).Omit("role").Updates(userdata)
    if result.Error != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "status":  500,
            "message": "Error updating user",
        })
    }

    // Return the updated user data
    return c.Status(fiber.StatusOK).JSON(fiber.Map{
        "message": "User updated successfully",
        "data":    existingUser,
    })
}



func (r *Repository) UpdateUser(c *fiber.Ctx) error {
	useradmin, err := r.UserAdmin(c)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }
    if useradmin != nil && *useradmin.Role == "admin" {

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
    } 
    return c.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")

}

func (r *Repository) DeleteAccount(context *fiber.Ctx) error {
    useradmin, err := r.UserAdmin(context)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    // Logout the user
    erro := r.LogoutUser(context)
    if erro != nil {
        // Handle error appropriately
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to logout user"})
    }

    // Delete the user account
    if err := r.DB.Delete(&models.Users{}, useradmin.ID).Error; err != nil {
        // Handle deletion error
        return context.Status(http.StatusInternalServerError).JSON(fiber.Map{
            "message": "Failed to delete your account",
        })
    }

    // Success response
    return context.Status(http.StatusOK).JSON(fiber.Map{
        "message": "You deleted your account and logged out successfully",
    })
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
    return context.Status(fiber.StatusForbidden).JSON("sorry, you can't use this method. You need to be an admin")
}}

func (r *Repository) GetUsers(context *fiber.Ctx) error {
    user, err := r.UserAdmin(context)
    if err != nil {
        // Handle error, e.g., user not found, not an admin, or other database errors
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

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

    if user != nil && *user.Role == "admin" {
        emOrNa := context.Params("em_or_na")
        if emOrNa == "" {
            context.Status(http.StatusBadRequest).JSON(&fiber.Map{
                "message": "send email or name  to search for a user.",
            })
            return nil
        }

        // Attempt to find user by email first
        userModel := &models.Users{}
        err := r.DB.Where("email = ?", emOrNa).First(userModel).Error
        if err != nil {
            if errors.Is(err, gorm.ErrRecordNotFound) {
                // If not found by email, try finding by name
                err = r.DB.Where("name = ?", emOrNa).First(userModel).Error
                if err != nil {
                    if errors.Is(err, gorm.ErrRecordNotFound) {
                        context.Status(http.StatusNotFound).JSON(
                            &fiber.Map{"message": "user not found by email or name"})
                    } else {
                        context.Status(http.StatusInternalServerError).JSON(
                            &fiber.Map{"message": "database error"})
                    }
                    return err
                }
            } else {
                context.Status(http.StatusInternalServerError).JSON(
                    &fiber.Map{"message": "database error"})
                return err
            }
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


func (r *Repository) Register(context *fiber.Ctx) error {
    useradmin, err := r.UserAdmin(context)
    if err != nil {
        return context.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
    }

    if useradmin != nil && *useradmin.Role == "admin" {
        user := User{}

        err := context.BodyParser(&user)
        if err != nil {
            return context.Status(http.StatusUnprocessableEntity).JSON(&fiber.Map{"message": "request failed"})
        }

        existingUser := models.Users{}
        if err := r.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
            return context.Status(http.StatusBadRequest).JSON(fiber.Map{"message": "email already exists"})
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
        if err != nil {
            return context.Status(http.StatusInternalServerError).JSON(&fiber.Map{"message": "could not hash password"})
        }
        user.Password = string(hashedPassword)

        if !isValidImageExtension(user.Image) {
            return context.Status(http.StatusBadRequest).JSON(&fiber.Map{"message": "invalid image file extension, only .jpg and .png are allowed"})
        }

        if !isValidEmail(user.Email) {
            return context.Status(http.StatusBadRequest).JSON(&fiber.Map{"message": "invalid email format"})
        }
/* 
        // Correctly handle file upload and get the file path
        filePath, err := r.handleFileUpload(context)
        if err != nil {
            return err // This will return the error from handleFileUpload
        }
        user.Image = filePath
*/
        err = r.DB.Create(&user).Error
        if err != nil {
            return context.Status(http.StatusBadRequest).JSON(&fiber.Map{"message": "could not create user"})
        }

        return context.Status(http.StatusOK).JSON(&fiber.Map{"message": "Add User Successfully"})
    }

    return context.Status(fiber.StatusForbidden).JSON(&fiber.Map{"message": "sorry u can't use this method you need to be admin"})
}
/*
func (r *Repository) handleFileUpload(c *fiber.Ctx) (string, error) {
    file, err := c.FormFile("file")
    if err != nil {
        return "", c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": "No file provided"})
    }

    src, err := file.Open()
    if err != nil {
        return "", c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{"error": "Failed to open file"})
    }
    defer src.Close()

    tempFile, err := ioutil.TempFile("./uploads", "upload-*")
    if err != nil {
        return "", c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{"error": "Failed to create temporary file"})
    }
    defer tempFile.Close()

    _, err = io.Copy(tempFile, src)
    if err != nil {
        return "", c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{"error": "Failed to save file"})
    }

    newFilename := strconv.FormatInt(time.Now().UnixNano(), 10) + filepath.Ext(file.Filename)
    newFilePath := filepath.Join("./uploads", newFilename)
    if err := os.Rename(tempFile.Name(), newFilePath); err != nil {
        return "", c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{"error": "Failed to move file"})
    }

    return newFilePath, nil
}
*/


func (r *Repository) LogoutUser(c *fiber.Ctx) error {
    // Clear the JWT token cookie 'make new one'
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
