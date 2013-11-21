package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "strconv"
  "github.com/whitney/auth"
  "github.com/jmoiron/sqlx"
  _ "github.com/lib/pq"
)

const (
  minPwdLen int = 5
  minUnameLen int = 1
)

var db *sqlx.DB

func main() {
  var err error
  // Connect to a database and verify with a ping.
  // postgres://uname:pwd@host/dbname?sslmode=disable
  dbUrl := os.Getenv("PG_HOST")
  db, err = sqlx.Connect("postgres", dbUrl)
  if err != nil {
    panic(err)
  }

  http.HandleFunc("/auth/signup", signup)
  http.HandleFunc("/auth/login", login)
  http.HandleFunc("/auth/logout", logout)
  http.HandleFunc("/auth/authenticated", authenticated)

  log.Println("listening...")
  err = http.ListenAndServe(":"+os.Getenv("AUTH_PORT"), nil)
  if err != nil {
    panic(err)
  }
}

// API
func authenticated(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  user, err := auth.AuthenticateUser(db, req)
  if err != nil {
    http.Error(res, err.Error(), http.StatusUnauthorized)
    return
  }

  jsonStr, err := user.Json()
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

// API
func signup(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 

  username := req.FormValue("username")
  if len(username) < minUnameLen {
    http.Error(res, "username missing", http.StatusBadRequest)
    return
  }

  password := req.FormValue("password")
  if len(password) < minPwdLen {
    http.Error(res, "invalid password", http.StatusBadRequest)
    return
  }

  _, err := auth.QueryUserByUsername(db, username)
  if err == nil {
    http.Error(res, "username taken", http.StatusBadRequest)
    return
  }

  hashedPwd, err := auth.HashPassword(password)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  authTkn := auth.CreateAuthTkn()
  log.Printf("authTkn: %s", authTkn)

  user, err := auth.InsertUser(db, username, string(hashedPwd), authTkn)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  jsonStr, err := user.Json()
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

// API
func login(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 

  username := req.FormValue("username")
  if len(username) == 0 {
    http.Error(res, "username missing", http.StatusBadRequest)
    return
  }

  password := req.FormValue("password")
  if len(password) == 0 {
    http.Error(res, "password missing", http.StatusBadRequest)
    return
  }

  user, err := auth.QueryUserByUsername(db, username)
  if err != nil {
    http.Error(res, err.Error(), http.StatusNotFound)
    return
  }

  err = auth.CompareHashAndPassword(user.PasswordDigest, password)
  if err != nil {
    http.Error(res, err.Error(), http.StatusUnauthorized)
    return
  }

  uMap := make(map[string]string)
  uMap["id"] = strconv.Itoa(int(user.Id))
  uMap["username"] = user.Username
  jsonStr, err := auth.JsonWrapMap(uMap)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  err = auth.SetAuthCookie(user.AuthToken, res)
  if err != nil {
    http.Error(res, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintln(res, jsonStr)
}

// API
func logout(res http.ResponseWriter, req *http.Request) {
  res.Header().Set("Content-Type", "application/json") 
  auth.InvalidateAuthCookie(res)
  fmt.Fprintln(res, "{'msg': 'ok'}")
}
