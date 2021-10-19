package main

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var host string = goDotEnvVariable("DATABASE_HOST")
var port string = goDotEnvVariable("DATABASE_PORT")
var dbPassword string = goDotEnvVariable("DATABASE_PASSWORD")
var dbName string = goDotEnvVariable("DATABASE")
var dbUser string = goDotEnvVariable("DATABASE_USER")

func GetDatabase() (*gorm.DB, error) {
	log.Println("host=" + host)
	dsn := "host=" + host + " port=" + port + " user=" + dbUser + " password=" + dbPassword + " dbname=" + dbName + " TimeZone=Asia/Shanghai sslmode=disable"
	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalln("wrong database url")
	}

	sqldb, err := connection.DB()
	if err == nil {
		err = sqldb.Ping()
	}

	fmt.Println("connected to database")
	return connection, err
}
func InitialMigration() {
	connection, err := GetDatabase()
	defer Closedatabase(connection)
	if err == nil {
		connection.AutoMigrate(User{})
	}
}

func Closedatabase(connection *gorm.DB) {
	sqldb, err := connection.DB()
	if err != nil {
		log.Fatal("could not get database")
	}
	sqldb.Close()
}
func createUser(db *gorm.DB, user User) {
	db.Create(&user)
}
func getUser(db *gorm.DB, user User) User {
	var match User
	db.Raw("SELECT id, name, password, role FROM users WHERE name = ?", user.Name).Scan(&match)
	return match
}
