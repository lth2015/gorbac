package main

import (
	"errors"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"github.com/casbin/casbin"
	"github.com/julienschmidt/httprouter"
	"log"
)

var enforcer *casbin.Enforcer

type User struct {
	Name         string // Tenant
	Organization string // Subject
	Method       string // Action
	Path         string // Object
}

func init() {
	ef, err := casbin.NewEnforcerSafe("./authz_model.conf", "./authz_policy.csv")
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	enforcer = ef
}

func writeError(status int, message string, w http.ResponseWriter, err error) {
	log.Printf("ERROR: %s\n", err.Error())
	w.WriteHeader(status)
	w.Write([]byte(message))
}

func writeOk(message string, w http.ResponseWriter) {
	log.Printf("Successful\n")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(message))
}

func Auth(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil {
		panic(err)
	}

	// casbin enforce
	res, err := enforcer.EnforceSafe(user.Name, user.Organization, user.Path, user.Method)
	if err != nil {
		writeError(http.StatusInternalServerError, "ERROR", w, err)
		return
	}
	if res {
		writeOk("Ok", w)
	} else {
		writeError(http.StatusForbidden, "FORBIDDEN", w, errors.New("unauthorized"))
		return
	}


}

func main() {
	router := httprouter.New()
	router.POST("/auth", Auth)
	log.Fatal(http.ListenAndServe(":8080", router))
}

