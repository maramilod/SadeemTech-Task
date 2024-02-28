package models

import "gorm.io/gorm"

// User model represents a Classifications in the system
type Classification struct {
	ID		uint   `gorm:"primary key;autoIncrement" json:"id"`
	Name	string `json:"name"`
	Status	string `gorm:"type:varchar(255)" json:"status"`
}

func MigrateClassification(db *gorm.DB) error {
	err := db.AutoMigrate(&Classification{})
	return err
}
