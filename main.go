package main

import (
	"gojwt/controller"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/signin", controller.SignIn).Methods("POST")
	router.HandleFunc("/welcome", controller.Welcome).Methods("POST")
	router.HandleFunc("/refresh", controller.Refresh).Methods("POST")

	log.Fatal(http.ListenAndServe(":3030", router))

}
