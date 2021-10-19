package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

var tokens = make(map[uint64][2]string)

type User struct {
	ID       uint64 `json:"Id"`
	Name     string `json:"Name"`
	Password string `json:"Password"`
	Role     uint64 `json:"Role"`
}

var password string = hashAndSalt([]byte("Admin"))
var u = User{
	ID:       3,
	Name:     "Admin",
	Password: password,
	Role:     3,
}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func newAuthHandler(mainHandler fasthttp.RequestHandler, accessTTL int64, refreshTTL int64) fasthttp.RequestHandler {
	r := router.New()
	r.GET("/", isAuth(mainHandler))
	r.POST("/auth", authHandler(accessTTL, refreshTTL))
	r.POST("/logout", logout)
	r.POST("/refresh", refresh(accessTTL, refreshTTL))

	return r.Handler
}
func isAuth(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		err := TokenValid(ctx)
		if err != nil {
			ctx.Error(fasthttp.StatusMessage(fasthttp.StatusUnauthorized), fasthttp.StatusUnauthorized)
			return
		}
		next(ctx)
		ctx.SetStatusCode(fasthttp.StatusOK)

	}
}
func logout(ctx *fasthttp.RequestCtx) {
	err := TokenValid(ctx)
	if err != nil {
		ctx.Error(fasthttp.StatusMessage(fasthttp.StatusUnauthorized), fasthttp.StatusUnauthorized)
		return
	}
	token, err := parseToken(ctx)
	if err != nil {
		log.Println(err)
	}
	creds := token.Claims.(jwt.MapClaims)
	log.Println(creds)
	user_id := creds["user_id"].(float64)
	delete(tokens, uint64(user_id))
	ctx.SetBody([]byte("Logged out succesfully"))
	ctx.SetStatusCode(fasthttp.StatusOK)

}

func mainHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hi there")

}
func checkCreds(user User) (*User, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}
	match := getUser(db, user)
	if match.ID == 0 || !CheckPasswordHash(user.Password, match.Password) {
		return nil, errors.New("could not find user")
	}

	return &match, nil
}
func authHandler(accessTTL int64, refreshTTL int64) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var creds User
		err := json.Unmarshal((ctx.PostBody()), &creds)
		if err != nil {
			log.Println(err)
			return
		}

		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			log.Println(err)
		}

		user, err := checkCreds(creds)
		if err != nil {
			ctx.SetBody([]byte(err.Error()))
			return
		}
		token, err := GenerateJWT(user.ID, accessTTL, refreshTTL)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		var at Token
		at.AccessTokenString = token.AccessToken
		at.RefreshTokenString = token.RefreshToken
		result, err := json.Marshal(at)
		if err != nil {
			log.Println("could not resolve json: ", err)
			return
		}
		ctx.SetContentType("application/json")
		ctx.SetBody(result)
		ctx.SetStatusCode(fasthttp.StatusOK)
	}
}

func main() {

	AtExpires := time.Now().Add(time.Minute * 15).Unix()
	RtExpires := time.Now().Add(time.Hour * 24 * 7).Unix()
	fasthttp.ListenAndServe(":8080", newAuthHandler(mainHandler, AtExpires, RtExpires))

	//lol, err := GenerateJWT(1)

	//log.Println(lol.AccessToken, err)
	//log.Println(lol.RefreshToken, db, err)
}
