.PHONY: environment build format test clean server_storage lorem_example lorem_example_debug

environment:
	. ./scripts/start.sh && ./scripts/build.sh

build:
	./scripts/build.sh

format:
	ruff format .
	black .

test:
	pytest

clean:
	rm -rf output/*
	rm -rf logs/*

server_storage:
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3

lorem_example:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	hyboat encode --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum.txt

lorem_example_debug:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	hyboat encode --debug --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum.txt
