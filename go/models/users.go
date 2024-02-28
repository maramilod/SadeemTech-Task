package models

import "gorm.io/gorm"

type Users struct {
	ID			uint    `gorm:"primary key;autoIncrement" json:"id"`
	Name		*string `json:"name"`
	Image		*string `json:"image"`
	Email		*string `json:"email"`
	Password	*string `json:"password"`
	Role		*string `json:"role"`
}

func MigrateUsers(db *gorm.DB) error {
	err := db.AutoMigrate(&Users{})
	return err
}