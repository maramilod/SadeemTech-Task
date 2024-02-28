package models

type UserClassification struct {
	gorm.Model
	UserID				uint   `json:"user_id"`
	ClassificationID	uint	`json:"classification_id"`
}

func MigrateUserClassification(db *gorm.DB) error {
	err := db.AutoMigrate(&UserClassification{})
	return err
}
