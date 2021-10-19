package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/valyala/fasthttp"
)

func goDotEnvVariable(key string) string {

	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	return os.Getenv(key)
}

var Atsecretkey string = goDotEnvVariable("ACCESS_TOKEN_SECRET_KEY")
var Rtsecretkey string = goDotEnvVariable("REFRESH_TOKEN_SECRET_KEY")

type Token struct {
	AccessTokenString  string `json:"accessToken"`
	RefreshTokenString string `json:"refreshToken"`
}
type TokenDetails struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	AtExpires    int64  `json:"AtExpires"`
	RtExpires    int64  `json:"RtExpires"`
}

func GenerateJWT(userID uint64, AtExpires int64, RtExpires int64) (*TokenDetails, error) {
	JWTDetails := &TokenDetails{}
	JWTDetails.RtExpires = RtExpires
	JWTDetails.AtExpires = AtExpires

	var AtSigningKey = []byte(Atsecretkey)
	var RtSigningKey = []byte(Rtsecretkey)
	var err error

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userID
	atClaims["exp"] = JWTDetails.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	JWTDetails.AccessToken, err = at.SignedString([]byte(AtSigningKey))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userID
	rtClaims["exp"] = JWTDetails.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	JWTDetails.RefreshToken, err = rt.SignedString(RtSigningKey)
	if err != nil {
		log.Println("Something Went Wrong: ", err.Error())
		return nil, err
	}
	b := [2]string{JWTDetails.AccessToken, JWTDetails.RefreshToken}
	tokens[userID] = b
	return JWTDetails, nil
}
func extractToken(ctx *fasthttp.RequestCtx) string {
	bearerToken := ctx.Request.Header.Peek("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(string(bearerToken), " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}
func parseToken(ctx *fasthttp.RequestCtx) (*jwt.Token, error) {
	tokenString := extractToken(ctx)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(goDotEnvVariable("ACCESS_TOKEN_SECRET_KEY")), nil
	})
	log.Println(err)
	return token, err
}
func verifyToken(ctx *fasthttp.RequestCtx) (*jwt.Token, error) {
	tokenString := extractToken(ctx)
	token, err := parseToken(ctx)
	if err != nil {

		return nil, err
	}
	creds := token.Claims.(jwt.MapClaims)
	user_id := creds["user_id"].(float64)

	if tokens[uint64(user_id)][0] != tokenString {
		return nil, errors.New("invalid Token: could not find user")
	}

	return token, nil
}
func TokenValid(ctx *fasthttp.RequestCtx) error {
	token, err := verifyToken(ctx)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		return err

	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		return err
	}
	return nil
}
func refresh(accessTTL int64, refreshTTL int64) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		refreshTokenString := extractToken(ctx)
		rtToken, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
			//Make sure that the token method conform to "SigningMethodHMAC"
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("Rtsecretkey")), nil
		})
		if err != nil {
			if err.Error() == "Token has expired" {
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			} else {
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
			}
		}
		if rtToken == nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		creds := rtToken.Claims.(jwt.MapClaims)
		user_id := creds["user_id"].(float64)
		if tokens[uint64(user_id)][1] != refreshTokenString {
			log.Println(errors.New("invalid Token: could not find user"))
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}

		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			log.Println(err)
		}
		if _, ok := rtToken.Claims.(jwt.Claims); !ok && !rtToken.Valid {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			log.Println(err)
			return
		}
		delete(tokens, uint64(user_id))
		token, err := GenerateJWT(uint64(user_id), accessTTL, refreshTTL)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetBody([]byte(err.Error()))
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
