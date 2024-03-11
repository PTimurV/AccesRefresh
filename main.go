package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID      primitive.ObjectID `bson:"_id"`
	Name    string             `bson:"name"`
	Refresh string             `bson:"refresh"`
}

var usersCollection *mongo.Collection
var secretKey = "Go123"

func init() {
	clientOptions := options.Client().ApplyURI("mongodb://0.0.0.0:27017")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	usersCollection = client.Database("auth").Collection("users1")
}

func NewJWT(userID string, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Subject:   userID,
	})
	return token.SignedString([]byte(secretKey))
}

func newRefreshToken() (string, error) {
	b := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)
	_, err := r.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func heshRefreshToken(refreshToken string) string {
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(hashedRefreshToken)
}

func tokenGenerate(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "Пользователь не указан", http.StatusBadRequest)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Невалидный пользовательский ID", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": objectID}
	var user User
	err = usersCollection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Пользователь не найден", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Ошибка поиска пользователя по ID: %v", err), http.StatusInternalServerError)
		return
	}

	accessToken, err := NewJWT(userID, 15)
	if err != nil {
		http.Error(w, "Ошибка генерации access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := newRefreshToken()
	if err != nil {
		http.Error(w, "Ошибка генерации refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefreshTokenString := heshRefreshToken(refreshToken)

	update := bson.M{"$set": bson.M{"refresh": hashedRefreshTokenString}}
	result, err := usersCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Fatal(err)
	}

	if result.ModifiedCount == 0 {
		fmt.Println("Пользователь не найден или значение не было обновлено")
	} else {
		fmt.Println("Значение обновлено успешно")
	}

	response := map[string]string{
		"access_token":      accessToken,
		"refresh_token":     refreshToken,
		"heshRefresh_token": hashedRefreshTokenString,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func refreshTokens(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Header.Get("Authorization")
	if refreshToken == "" {
		http.Error(w, "В хедере авторизации нет refresh token", http.StatusUnauthorized)
		return
	}

	filter := bson.M{"refresh": refreshToken}

	var user User
	err := usersCollection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Пользователь не найден", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Ошибка поиска пользователя по ID: %v", err), http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := newRefreshToken()
	if err != nil {
		http.Error(w, "Ошибка генерации нового refresh token", http.StatusInternalServerError)
		return
	}

	hashedRefreshTokenString := heshRefreshToken(newRefreshToken)

	update := bson.M{"$set": bson.M{"refresh": hashedRefreshTokenString}}
	result, err := usersCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Fatal(err)
	}

	if result.ModifiedCount == 0 {
		fmt.Println("Пользователь не найден или значение не было обновлено")
	} else {
		fmt.Println("Значение обновлено успешно")
	}

	// Генерация нового access токена
	newAccessToken, err := NewJWT(user.ID.Hex(), 15)
	if err != nil {
		http.Error(w, "Ошибка генерации нового access token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":      newAccessToken,
		"refresh_token":     newRefreshToken,
		"heshRefresh_token": hashedRefreshTokenString,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/token", tokenGenerate)
	http.HandleFunc("/refresh", refreshTokens)

	fmt.Println("Server is running on :8001")
	log.Fatal(http.ListenAndServe(":8001", nil))
}
