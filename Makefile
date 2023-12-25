#Dockerfile vars
APP_NAME = "fritzbox-logs"

#vars
IMAGEFULLNAME=${APP_NAME}:latest

.PHONY: help build

help:
	    @echo "Makefile commands:"
	    @echo "build"
	    @echo "run"
	    @echo "all (default)"

.DEFAULT_GOAL := all

# Build the container
build:
		@podman build . -t ${IMAGEFULLNAME}

# Run the container
run:
		@podman run \
			-e 'url=$(FBURL)' \
			-e 'user=$(FBUSER)' \
			-e 'password=$(FBPASS)' \
			-e 'interval=$(FBINT)' \
			-e 'outputDir=$(FBAPPVOLUME)' \
			-v /Users/dkusidlo/development/tmp/fritzbox-logs-data:/data/fritzbox-logs-data ${IMAGEFULLNAME}

all: build run
