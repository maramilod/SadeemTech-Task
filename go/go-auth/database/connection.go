package database

import (
	"log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect() {

	dsn := "host=localhost port=5432 user=postgres password=new_password dbname=yt_go_auth sslmode=disable"
                db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

				if err != nil {
					log.Fatalf("couldn't connect to the database: %v", err)
				}
			
				// It's a good practice to check if the connection is alive
				sqlDB, err := db.DB()
				if err != nil {
					log.Fatalf("failed to get underlying SQL DB: %v", err)
				}
				defer sqlDB.Close()
}

