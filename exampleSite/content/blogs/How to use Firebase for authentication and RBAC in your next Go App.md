---
title: "Authenticating your next Go App"
date: 2024-10-03T22:53:58+05:30
draft: false
github_link: "https://github.com/gurusabarish/hugo-profile"
author: "charles dpj"
tags:
  - Go
  - Auth
  - Firebase
image: https://miro.medium.com/v2/resize:fit:720/format:webp/1*XHpA-jtG4sunRRFzvCMplQ.png
description: ""
toc: 
---



# Implementing Firebase Authentication and Role-Based Access Control (RBAC) in Go

## Introduction

Authentication is crucial for any application that wants to keep user data secure. Security and the protection of users’ information are paramount. There are various methods for handling authentication, but for this particular case, we’ll focus on using a third-party identity platform. You might be wondering, **"Why not build our own authentication system?"** Well, there are a few reasons. Compliance requirements for authentication can be tedious and time-consuming, and if not done properly, can leave your application vulnerable to attacks. To avoid this headache, it makes sense to use a trusted third-party service that specializes in security. Therefore, for these reasons, we have chosen to use a third-party identity platform.

## 3rd-party Identity Services

Few examples of such third-party services are Firebase, Asgardeo, Keycloak, OneLogin, Auth0, and Okta. In this article, we will be using Firebase as the auth provider. It is very quick to set up, works out of the box, and has a very generous free tier that we can leverage.

## Concept

The authentication process is quite simple. When a user tries to sign in, the client (web or mobile) sends a request to the Firebase server. The Firebase server returns an `id_token`. In this case, the token is configured to be JWT. The `id_token` is used by the client to know if a user is authenticated. The `id_token` is also used to authenticate API calls made to backend APIs.

## Setting Up Firebase

1. **Create a Firebase Project**  
   Open up the Firebase console to create a new Firebase project.
   - Enter the name of your project.
   - You don’t necessarily need Google Analytics, so you can skip that.
   - Once you’ve successfully created the Firebase project, navigate to your project: `Build > Authentication`.

2. **Set Up Authentication Methods**  
   - Select Google as the sign-in method and enable it. Navigate to `Sign-in method > Google`.
   - You can add as many methods as needed, but for the sake of keeping this project simple, I will only use Google authentication.

3. **Download the Firebase Service Account Key**  
   - Navigate to `Settings > Project Settings > Service Accounts`.
   - Select Go and click on ‘Generate New Key’.
   - This will download a JSON file. Move this file into the root directory of your Go project later on.

## Setting Up the Go Project

1. **Initialize Go Module**  
   - Create a directory where the project will be stored and initialize go mod inside of it.
     ```bash
     mkdir fire-go
     cd fire-go
     go mod init github.com/github_username/fire-go-auth
     ```

2. **Install Dependencies**  
   - For this project, you will utilize some dependencies:
     ```bash
     go get "firebase.google.com/go/v4/"
     go get "firebase.google.com/go/v4/auth"
     go get "github.com/gin-gonic/gin"
     go get "github.com/gin-contrib/cors"
     go get "github.com/joho/godotenv"
     ```

3. **Configure Environment Variables**  
   - Rename the Firebase key we downloaded earlier to ‘private_key.json’ and move it into the root directory of your project.
   - Create a `.env` file and a `.gitignore` file to store it securely:
     ```bash
     touch .env
     touch .gitignore
     ```
   - Add the following to your `.env` file:
     ```
     FIREBASE_KEY=private_key.json
     ```
   - Include the following in your `.gitignore` file to ensure sensitive information is not exposed to version control:
     ```
     .env
     private_key.json
     ```

4. **Set Up Authentication Middleware**  
   - Create a new directory called `middleware`, this directory will hold all of your auth logic.
     ```bash
     mkdir middleware
     cd middleware
     touch auth.go
     ```

## Initializing Firebase into the Golang App

1. **Integrate Firebase with the Go Server**  
   - To integrate Firebase with your Go server, you need to set up the Firebase Admin SDK. The configuration will instantiate a new Firebase app instance, which will establish a connection to Firebase for each incoming request.


## **Function: InitAuth()**

```go
func InitAuth() (*auth.Client, error) {
	var firebaseCredFile = os.Getenv("FIREBASE_KEY")
	opt := option.WithCredentialsFile(firebaseCredFile)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing firebase app: %v", err)
		return nil, err
	}
	
	client, errAuth := app.Auth(context.Background())
	if errAuth != nil {
		log.Fatalf("error initializing firebase auth: %v", errAuth)
		return nil, errAuth
	}
	
	return client, nil
}
```

### **Setting up Authentication and Authorization**

Next, we’ll create a middleware that ensures incoming requests are properly authenticated before granting access to our service. The middleware will extract the authorization header from the ID token in incoming requests and verify the ID token with Firebase. If the ID token is valid, access will be granted.

```go
func Auth(client *auth.Client) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		startTime := time.Now()

		header := ctx.Request.Header.Get("Authorization")
		if header == "" {
			log.Println("Missing Authorization header")
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
			return
		}
		idToken := strings.Split(header, "Bearer ")
		if len(idToken) != 2 {
			log.Println("Invalid Authorization header")
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
			return
		}
		tokenID := idToken[1]

		token, err := client.VerifyIDToken(context.Background(), tokenID)
		if err != nil {
			log.Printf("Error verifying token. Error: %v\n", err)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
			return
		}

		log.Println("Auth time:", time.Since(startTime))
		ctx.Next()
	}
}
```

After a user is granted access to our services, it’s important to regulate what they are permitted to use. This can be effectively managed by assigning roles to each user. A role defines a set of permissions that usually correspond to a business function. Typically, users get their permissions through their roles. Firebase simplifies the process of assigning users roles by using a feature called custom claims. Custom claims allow you to attach additional information to a user’s ID token. During the authentication process, we can verify the user’s ID token, extract these claims, and determine which services they are authorized to access.

### **Assign Role Function**

```go
func AssignRole(ctx context.Context, client *auth.Client, email string, role string) error {
	user, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		log.Printf("Assign Error: User with email %s not found", email)
		return ErrUserNotFound
	}
	currentCustomClaims := user.CustomClaims
	if currentCustomClaims == nil {
		currentCustomClaims = map[string]interface{}{}
	}
	currentCustomClaims["role"] = role
	if err := client.SetCustomUserClaims(ctx, user.UID, currentCustomClaims); err != nil {
		return fmt.Errorf("AssignRole Error: Error setting custom claims: %w", err)
	}
	return nil
}
```

### **Auth Middleware Enhancements**

The Auth middleware extracts the user details from the token claims, populates a custom `User` struct with this information, and stores it in the context of the current request.

```go
type User struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

email, ok := token.Claims["email"].(string)
if !ok {
	log.Println("Email claim not found in token")
	ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
	return
}
log.Println("auth email is ", email)

role := token.Claims["role"].(string)
user := &User{
	UserID: token.UID,
	Email:  email,
	Role:   role,
}

ctx.Set("user", user)
```

### **Role Assignment Logic**

We assign roles to users during the authentication process based on their email and the claims in their ID token. This ensures that new users are automatically assigned a role when they first sign up:

```go
adminEmail := os.Getenv("ADMIN_EMAIL")
role, ok := token.Claims["role"].(string)

if email == adminEmail && role == "user" {
	startTime := time.Now()
	if err := AssignRole(ctx, client, adminEmail, "admin"); err != nil {
		log.Printf("Error assigning admin role to %s: %v\n", adminEmail, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}
	log.Println("Admin role assigned in:", time.Since(startTime))
	role = "admin"
}
if !ok {
	startTime := time.Now()
	if err := AssignRole(ctx, client, email, "user"); err != nil {
		log.Printf("Error assigning user role to %s: %v\n", email, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}
	log.Println("User role assigned in:", time.Since(startTime))
	role = "user"
}
```

### **Role Authorization Middleware**

To protect routes based on user roles, we create a middleware function that checks if the signed-in user has the required role for a specific route:

```go
func RoleAuth(requiredRole string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userValue, exists := ctx.Get("user")
		if !exists {
			log.Println("User not found in context")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		user, ok := userValue.(*User)
		if !ok || user == nil {
			log.Println("Invalid user data in context")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if user.Role == "" {
			log.Println("User role not set")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if user.Role != requiredRole {
			log.Printf("User with email %s and role %s tried to access a route that was for the %s role only",
				user.Email, user.Role, requiredRole)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		log.Printf("User with email %s and role %s authorized", user.Email, user.Role)
		ctx.Next()
	}
}
```

### **RBAC Management Service**

With our authentication and authorization setup complete, let’s implement a service that enables us to manage admin privileges through HTTP requests. This service will use the `AssignRole` function flow we discussed earlier to change a user’s access level. The process involves sending a user’s email to the backend server via an HTTP request. If the email is valid, the user can either be made an admin or have their admin access revoked.

```go
// Your service code goes here to handle role management via HTTP requests.
```

Here's the refactored code for the provided functions and methods in Go:

1. **InitAuth Function**:
```go
func InitAuth() (*auth.Client, error) {
	var firebaseCredFile = os.Getenv("FIREBASE_KEY")
	opt := option.WithCredentialsFile(firebaseCredFile)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing firebase app: %v", err)
		return nil, err
	}
	client, errAuth := app.Auth(context.Background())
	if errAuth != nil {
		log.Fatalf("error initializing firebase auth: %v", errAuth)
		return nil, errAuth
	}
	return client, nil
}
```

2. **Auth Middleware**:
```go
func Auth(client *auth.Client) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		startTime := time.Now()

		header := ctx.Request.Header.Get("Authorization")
		if header == "" {
			log.Println("Missing Authorization header")
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
			return
		}
		idToken := strings.Split(header, "Bearer ")
		if len(idToken) != 2 {
			log.Println("Invalid Authorization header")
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
			return
		}
		tokenID := idToken[1]

		token, err := client.VerifyIDToken(context.Background(), tokenID)
		if err != nil {
			log.Printf("Error verifying token. Error: %v\n", err)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, Invalid Token"})
			return
		}

		log.Println("Auth time:", time.Since(startTime))
		ctx.Next()
	}
}
```

3. **AssignRole Function**:
```go
func AssignRole(ctx context.Context, client *auth.Client, email string, role string) error {
	user, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		log.Printf("Assign Error: User with email %s not found", email)
		return ErrUserNotFound
	}
	currentCustomClaims := user.CustomClaims
	if currentCustomClaims == nil {
		currentCustomClaims = map[string]interface{}{}
	}
	currentCustomClaims["role"] = role
	if err := client.SetCustomUserClaims(ctx, user.UID, currentCustomClaims); err != nil {
		return fmt.Errorf("AssignRole Error: Error setting custom claims: %w", err)
	}
	return nil
}
```

4. **AdminService Interface and Implementation**:
```go
type AdminService interface {
	MakeAdmin(email string) error
	RemoveAdmin(email string) error
}

type AdminServiceImpl struct {
	client *auth.Client
}

func NewAdminService(client *auth.Client) *AdminServiceImpl {
	return &AdminServiceImpl{client: client}
}

func (s *AdminServiceImpl) MakeAdmin(email string) error {
	if err := middleware.AssignRole(context.Background(), s.client, email, "admin"); err != nil {
		log.Printf("Error assigning admin role: %v", err)
		return err
	}
	return nil
}

func (s *AdminServiceImpl) RemoveAdmin(email string) error {
	if err := middleware.AssignRole(context.Background(), s.client, email, "user"); err != nil {
		log.Printf("Error assigning user role: %v", err)
		return err
	}
	return nil
}
```

5. **HTTP Handlers in http.go**:
```go
var (
	ErrInvalidEmail = errors.New("invalid email")
	ErrInvalidJson  = errors.New("invalid JSON format")
)

type EmailInput struct {
	Email string `json:"email"`
}

func MakeAdminHandler(ctx *gin.Context, service AdminService) {
	var input EmailInput
	if err := ctx.BindJSON(&input); err != nil {
		log.Printf("Error binding JSON: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidJson})
		return
	}

	emailOk := validateEmail(input.Email)
	if !emailOk {
		log.Printf("Error validating email invalid email format: %v", input.Email)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrInvalidEmail})
		return
	}

	if err := service.MakeAdmin(input.Email); err != nil {
		log.Printf("Error assigning admin role: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s is now an admin", input.Email)})
}

func RemoveAdminHandler(ctx *gin.Context, service AdminService) {
	var input EmailInput
	if err := ctx.BindJSON(&input); err != nil {
		log.Printf("Error binding JSON: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidJson})
		return
	}

	emailOk := validateEmail(input.Email)
	if !emailOk {
		log.Printf("Error validating email invalid email format: %v", input.Email)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrInvalidEmail})
		return
	}

	if err := service.RemoveAdmin(input.Email); err != nil {
		log.Printf("Error assigning user role: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s admin rights have been revoked", input.Email)})
}
```

6. **Validation Utility in util.go**:
```go
func validateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}
```

7. **main.go Setup**:
```go
func main() {
	// Load environment variables
	err := godotenv.Load("./.env")
	if err != nil {
		log.Fatal("Error loading .env file", err)
	}
	log.Println(".env file loaded successfully")

	// Initialize Firebase Auth
	client, err := middleware.InitAuth()
	if err != nil {
		log.Fatalf("Error initializing Firebase auth: %v", err)
	}

	// Set up Gin server
	r := gin.Default()
	r.Use(cors.Default())

	// Define routes
	RegisterRoutes(r, client)
	RegisterAdminRoutes(r, client)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Gin server is running on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start Gin server: %v", err)
	}
}

func RegisterRoutes(r *gin.Engine, client *auth.Client) {
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "fire-go-auth success")
	})
	r.GET("/user", middleware.Auth(client), func(c *gin.Context) {
		user, ok := c.Get("user")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User details not found"})
			return
		}
		userDetails := user.(*middleware.User)
		c.JSON(http.StatusOK, userDetails)
	})
}

func RegisterAdminRoutes(r *gin.Engine, client *auth.Client) {
	adminService := role.NewAdminService(client)

	adminRoutes := r.Group("/admin")
	adminRoutes.Use(middleware.Auth(client), middleware.RoleAuth("admin"))
	{
		adminRoutes.GET("/", func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "admin")
		})
		adminRoutes.POST("/make", func(ctx *gin.Context) {
			role.MakeAdminHandler(ctx, adminService)
		})
		adminRoutes.DELETE("/remove", func(ctx *gin.Context) {
			role.RemoveAdminHandler(ctx, adminService)
		})
	}
}
```

