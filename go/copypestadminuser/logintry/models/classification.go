package models

type Classification struct {
	ID     uint   `gorm:"primary key;autoIncrement" json:"id"`
	Status string `gorm:"type:varchar(255)" json:"status"`
}

func MigrateClassification(db *gorm.DB) error {
	err := db.AutoMigrate(&Classification{})
	return err
}
