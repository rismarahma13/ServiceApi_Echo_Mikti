package main

import (
	"net/http"
	"time"

	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB
var jwtSecret = []byte("your_secret_key") // Ganti dengan secret key yang aman

// Model User
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"unique" json:"username"`
	Password  string    `json:"-"`
	Role      string    `json:"role"` // admin atau editor
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Model Todo
type Todo struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Struktur JWT Claims
type JwtCustomClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Fungsi utama
func main() {
	var err error
	// Hubungkan ke database SQLite yang sudah ada
	db, err = gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}

	// Optional: Pastikan model sesuai dengan tabel yang ada
	// Jika Anda yakin tabel sudah sesuai, Anda bisa mengomentari baris berikut
	// db.AutoMigrate(&User{}, &Todo{})

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Pastikan admin default ada jika tidak ada
	createDefaultAdmin()

	// Routes publik
	e.POST("/login", login)

	// Routes yang memerlukan JWT
	r := e.Group("/api")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: jwtSecret,
		Claims:     &JwtCustomClaims{},
	}))

	// CRUD Todo (hanya role editor)
	r.GET("/todos", getTodos, roleMiddleware("editor"))
	r.POST("/todos", createTodo, roleMiddleware("editor"))
	r.PUT("/todos/:id", updateTodo, roleMiddleware("editor"))
	r.DELETE("/todos/:id", deleteTodo, roleMiddleware("editor"))

	// CRUD User (hanya role admin)
	r.GET("/users", getUsers, roleMiddleware("admin"))
	r.POST("/users", createUser, roleMiddleware("admin"))
	r.PUT("/users/:id", updateUser, roleMiddleware("admin"))
	r.DELETE("/users/:id", deleteUser, roleMiddleware("admin"))

	e.Logger.Fatal(e.Start(":8080"))
}

// Middleware untuk memeriksa peran (RBAC)
func roleMiddleware(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user").(*jwt.Token)
			claims := user.Claims.(*JwtCustomClaims)
			if claims.Role != role {
				return c.JSON(http.StatusForbidden, map[string]string{"message": "Access forbidden"})
			}
			return next(c)
		}
	}
}

// Handler login
func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid username or password"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid username or password"})
	}

	// Buat token JWT
	claims := &JwtCustomClaims{
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString(jwtSecret)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{"token": t})
}

// CRUD User
func getUsers(c echo.Context) error {
	var users []User
	db.Find(&users)
	// Jangan kembalikan password
	for i := range users {
		users[i].Password = ""
	}
	return c.JSON(http.StatusOK, users)
}

func createUser(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	role := c.FormValue("role")

	if username == "" || password == "" || role == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Missing fields"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Error hashing password"})
	}

	user := User{Username: username, Password: string(hashedPassword), Role: role}
	if err := db.Create(&user).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not create user"})
	}

	user.Password = "" // Jangan kembalikan password
	return c.JSON(http.StatusCreated, user)
}

func updateUser(c echo.Context) error {
	id := c.Param("id")
	var user User
	if err := db.First(&user, id).Error; err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "User not found"})
	}

	username := c.FormValue("username")
	password := c.FormValue("password")
	role := c.FormValue("role")

	if username != "" {
		user.Username = username
	}
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Error hashing password"})
		}
		user.Password = string(hashedPassword)
	}
	if role != "" {
		user.Role = role
	}

	if err := db.Save(&user).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not update user"})
	}

	user.Password = "" // Jangan kembalikan password
	return c.JSON(http.StatusOK, user)
}

func deleteUser(c echo.Context) error {
	id := c.Param("id")
	var user User
	if err := db.First(&user, id).Error; err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "User not found"})
	}

	if err := db.Delete(&user).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not delete user"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User deleted"})
}

// CRUD Todo
func getTodos(c echo.Context) error {
	var todos []Todo
	db.Find(&todos)
	return c.JSON(http.StatusOK, todos)
}

func createTodo(c echo.Context) error {
	title := c.FormValue("title")
	content := c.FormValue("content")

	if title == "" || content == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Missing fields"})
	}

	todo := Todo{Title: title, Content: content, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&todo).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not create todo"})
	}

	return c.JSON(http.StatusCreated, todo)
}

func updateTodo(c echo.Context) error {
	id := c.Param("id")
	var todo Todo
	if err := db.First(&todo, id).Error; err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "Todo not found"})
	}

	title := c.FormValue("title")
	content := c.FormValue("content")

	if title != "" {
		todo.Title = title
	}
	if content != "" {
		todo.Content = content
	}
	todo.UpdatedAt = time.Now()

	if err := db.Save(&todo).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not update todo"})
	}

	return c.JSON(http.StatusOK, todo)
}

func deleteTodo(c echo.Context) error {
	id := c.Param("id")
	var todo Todo
	if err := db.First(&todo, id).Error; err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "Todo not found"})
	}

	if err := db.Delete(&todo).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not delete todo"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Todo deleted"})
}

// Membuat admin default jika tidak ada
func createDefaultAdmin() {
	var count int64
	db.Model(&User{}).Where("role = ?", "admin").Count(&count)
	if count == 0 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), 14)
		if err != nil {
			fmt.Println("Error hashing default admin password:", err)
			return
		}
		admin := User{Username: "admin", Password: string(hashedPassword), Role: "admin", CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := db.Create(&admin).Error; err != nil {
			fmt.Println("Error creating default admin:", err)
			return
		}
		fmt.Println("Default admin created: username=admin, password=admin123")
	}
}
