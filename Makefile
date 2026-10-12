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
	hybolt encode --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum.txt
	hybolt decode --server-file examples/server_list_example.json --output-file output/lorem_ipsum_decoded.txt output/lorem_ipsum_metadata.pkl
	python scripts/compare_files.py examples/lorem_ipsum.txt output/lorem_ipsum_decoded.txt

lorem_example_debug:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	hybolt encode --debug --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum.txt
	hybolt decode --debug --server-file examples/server_list_example.json --output-file output/lorem_ipsum_decoded.txt output/lorem_ipsum_metadata.pkl
	python scripts/compare_files.py examples/lorem_ipsum.txt output/lorem_ipsum_decoded.txt
