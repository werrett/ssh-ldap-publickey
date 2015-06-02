package main

import (
	"errors"
	"log"
	"os"
)

/*
 * Generic helper functions
 */

func check(e error) {
	if e != nil {
		if flagVerbose {
			log.Fatal(e)
		} else {
			os.Exit(1)
		}
	}
}

func newError(str string) {
	err := errors.New(str)
	check(err)
}
