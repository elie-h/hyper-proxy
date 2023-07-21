package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/segmentio/ksuid"
	"golang.org/x/net/http2"
)

type Account struct {
	ID           string    `gorm:"type:varchar(27);primary_key;"`
	Name         string    `gorm:"type:varchar(100)"`
	RequestLimit int       `gorm:"type:int"`
	CallCount    int       `gorm:"type:int"`
	CreatedAt    time.Time `gorm:"type:datetime"`
	UpdatedAt    time.Time `gorm:"type:datetime"`
}

type CreateAccountResponse struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RequestLimit int       `json:"request_limit"`
	CallCount    int       `json:"call_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	APIKey       string    `json:"api_key"`
}

type AccountService interface {
	GetAccount(apiKey string) (*Account, error)
	CreateAccount(name string, requestLimit int) (*CreateAccountResponse, error)
	UpdateAccount(account *Account) error
}

type GormAccountService struct {
	db     *gorm.DB
	secret []byte
}

func (s *GormAccountService) GetAccount(apiKey string) (*Account, error) {
	var account Account
	if s.db.Where("id = ?", apiKey).First(&account).RecordNotFound() {
		return nil, &ErrAccountNotFound{APIKey: apiKey}
	}
	return &account, nil
}

func GenerateId() string {
	ksuid := ksuid.New()
	return ksuid.String()
}

func (s *GormAccountService) CreateAccount(name string, requestLimit int) (*CreateAccountResponse, error) {
	id := GenerateId()
	account := Account{
		ID:           id,
		Name:         name,
		RequestLimit: requestLimit,
	}

	if result := s.db.Create(&account); result.Error != nil {
		return nil, result.Error
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id": account.ID,
	})

	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return nil, err
	}

	return &CreateAccountResponse{
		ID:           account.ID,
		Name:         account.Name,
		RequestLimit: account.RequestLimit,
		CallCount:    account.CallCount,
		CreatedAt:    account.CreatedAt,
		UpdatedAt:    account.UpdatedAt,
		APIKey:       tokenString,
	}, nil
}

func (s *GormAccountService) UpdateAccount(account *Account) error {
	return s.db.Save(account).Error
}

type key int

const (
	AttributionKey key = iota
)

func authMiddleware(handler http.HandlerFunc, accountService AccountService, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			writeJSONResponse(w, http.StatusProxyAuthRequired, "Proxy authorization required")
			return
		}

		authParts := strings.Split(authHeader, " ")
		if len(authParts) != 2 || strings.ToLower(authParts[0]) != "basic" {
			writeJSONResponse(w, http.StatusBadRequest, "Invalid proxy authorization header")
			return
		}

		payload, err := base64.StdEncoding.DecodeString(authParts[1])
		if err != nil {
			writeJSONResponse(w, http.StatusBadRequest, "Invalid proxy authorization header")
			return
		}
		userPassParts := strings.Split(string(payload), ":")
		if len(userPassParts) != 2 {
			writeJSONResponse(w, http.StatusBadRequest, "Invalid proxy authorization header")
			return
		}

		attribution := userPassParts[0]
		tokenString := userPassParts[1] // The password is now the JWT

		// Parse the token.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		})

		if err != nil {
			writeJSONResponse(w, http.StatusBadRequest, "Invalid JWT")
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Extract the account id
			id := claims["id"].(string)
			account, err := accountService.GetAccount(id)
			if err != nil {
				writeJSONResponse(w, http.StatusUnauthorized, err.Error())
				return
			}

			if account == nil {
				writeJSONResponse(w, http.StatusUnauthorized, "Invalid API key")
				return
			}

			// Check rate limit
			if account.CallCount >= account.RequestLimit {
				writeJSONResponse(w, http.StatusTooManyRequests, "Rate limit exceeded")
				return
			}

			// Increment the call count
			account.CallCount++
			if err := accountService.UpdateAccount(account); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), AttributionKey, attribution)
			r = r.WithContext(ctx)
			handler.ServeHTTP(w, r)
		} else {
			writeJSONResponse(w, http.StatusBadRequest, "Invalid JWT")
			return
		}
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	attribution := r.Context().Value(AttributionKey).(string)
	start := time.Now()

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeJSONResponse(w, http.StatusInternalServerError, "Proxying not supported")
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to proxy connection")
		return
	}

	var bytesTransferred int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer destConn.Close()

		bytes, _ := io.Copy(destConn, clientConn)
		atomic.AddInt64(&bytesTransferred, bytes)
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()

		bytes, _ := io.Copy(clientConn, destConn)
		atomic.AddInt64(&bytesTransferred, bytes)
	}()

	wg.Wait()
	log.Printf("Attribution: %v, CONNECT to %s. Origin: %s, Duration: %s, Bytes Transferred: %d", attribution, r.Host, r.RemoteAddr, time.Since(start), bytesTransferred)
}

type ConnectHandler struct {
	accountService *GormAccountService
}

func (h *ConnectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		writeJSONResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	authMiddleware(handleTunneling, h.accountService, h.accountService.secret).ServeHTTP(w, r)
}

func writeJSONResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Proxy-Error", message)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

type RegisterRequest struct {
	Name         string `json:"name" validate:"min=1,max=100"`
	RequestLimit int    `json:"request_limit" validate:"required,min=1"`
}

func createAccountHandler(w http.ResponseWriter, r *http.Request, accountService AccountService) {
	var requestData RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to parse request body: %v", err))
		return
	}

	validate := validator.New()
	if err := validate.Struct(requestData); err != nil {
		validationErrors := err.(validator.ValidationErrors)

		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, fmt.Sprintf("Field error in struct 'RegisterRequest' on field '%s', condition: %s", err.Field(), err.Tag()))
		}

		writeJSONResponse(w, http.StatusBadRequest, strings.Join(errorMessages, ", "))
		return
	}

	newAccount, err := accountService.CreateAccount(requestData.Name, requestData.RequestLimit)
	if err != nil {
		switch err := err.(type) {
		default:
			writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create account: %v", err))
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newAccount)
}

func getAccountHandler(w http.ResponseWriter, r *http.Request, accountService AccountService, accountID string) {
	account, err := accountService.GetAccount(accountID)
	if err != nil {
		writeJSONResponse(w, http.StatusNotFound, fmt.Sprintf("Failed to find account: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(account)
}

func main() {
	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	db.AutoMigrate(&Account{})

	accountService := &GormAccountService{
		db:     db,
		secret: []byte("YourSecretKey"),
	}

	server := http.Server{
		Addr: "localhost:8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				accountID := strings.TrimPrefix(r.URL.Path, "/account/")
				if accountID != "" && accountID != r.URL.Path {
					getAccountHandler(w, r, accountService, accountID)
					return
				}
			case http.MethodPost:
				if r.URL.Path == "/account" {
					createAccountHandler(w, r, accountService)
					return
				}
			}

			handler := handleErrors(&ConnectHandler{
				accountService: accountService,
			})

			handler.ServeHTTP(w, r)
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return ctx
		},
	}

	http2.ConfigureServer(&server, nil)
	log.Fatal(server.ListenAndServe())
}

// Errors
type ErrAccountNotFound struct {
	APIKey string
}

func (e *ErrAccountNotFound) Error() string {
	return fmt.Sprintf("Account not found for API key: %s", e.APIKey)
}

type ErrInvalidAPIKey struct{}

func (e *ErrInvalidAPIKey) Error() string {
	return "Invalid API key"
}

type ErrRateLimitExceeded struct{}

func (e *ErrRateLimitExceeded) Error() string {
	return "Rate limit exceeded"
}

type ErrBadRequest struct {
	Reason string
}

func (e *ErrBadRequest) Error() string {
	return fmt.Sprintf("Bad request: %s", e.Reason)
}

func handleErrors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				var err error
				switch t := r.(type) {
				case string:
					err = errors.New(t)
				case error:
					err = t
				default:
					err = errors.New("unknown error")
				}
				fmt.Println("Stacktrace from panic: \n" + string(debug.Stack()))
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}
