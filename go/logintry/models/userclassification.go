package models

import "gorm.io/gorm"

// The User model represents a user's classifications in the system
type UserClassification struct {
	gorm.Model
	UserID				uint   `json:"user_id"`
	UserName			*string   `json:"user_name"`
	ClassificationID	uint	`json:"clasf_id"`
	ClassificationName	string	`json:"clasf_name"`
}

func MigrateUserClassification(db *gorm.DB) error {
	err := db.AutoMigrate(&UserClassification{})
	return err
}
