.PHONY: environment build format test clean server_storage lorem_example lorem_example_debug big_lorem_example big_lorem_example_debug all_lorem_ipsum_sizes binary_example

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
	hybolt encode --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum/3kib.txt
	hybolt decode --server-file examples/server_list_example.json --output-file output/3kib_decoded.txt output/3kib_metadata.pkl
	python scripts/compare_files.py examples/lorem_ipsum/3kib.txt output/3kib_decoded.txt

lorem_example_debug:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	hybolt encode --debug --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum/3kib.txt
	hybolt decode --debug --server-file examples/server_list_example.json --output-file output/3kib_decoded.txt output/3kib_metadata.pkl
	python scripts/compare_files.py examples/lorem_ipsum/3kib.txt output/3kib_decoded.txt

big_lorem_example:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	hybolt encode --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum/1024kib.txt
	hybolt decode --server-file examples/server_list_example.json --output-file output/1024kib_decoded.txt output/1024kib_metadata.pkl
	python scripts/compare_files.py examples/lorem_ipsum/1024kib.txt output/1024kib_decoded.txt

big_lorem_example_debug:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	hybolt encode --debug --server-list examples/server_list_example.json --metadata-output output/ examples/lorem_ipsum/1024kib.txt
	hybolt decode --debug --server-file examples/server_list_example.json --output-file output/1024kib_decoded.txt output/1024kib_metadata.pkl
	python scripts/compare_files.py examples/lorem_ipsum/1024kib.txt output/1024kib_decoded.txt

all_lorem_ipsum_sizes:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	set -e; for input_file in examples/lorem_ipsum/*.txt; do \
		if [ "$$(wc -c < "$$input_file")" -ge 4194304 ]; then continue; fi; \
		file_name=$$(basename "$$input_file" .txt); \
		output_file="output/$${file_name}_decoded.txt"; \
		hybolt encode --server-list examples/server_list_example.json --metadata-output output/ "$$input_file"; \
		hybolt decode --server-file examples/server_list_example.json --output-file "$$output_file" "output/$${file_name}_metadata.pkl"; \
		python scripts/compare_files.py "$$input_file" "$$output_file"; \
	done

binary_example:
	rm -rf output/*
	rm -rf logs/*
	./scripts/build.sh
	mkdir -p output/server_storage/server_1
	mkdir -p output/server_storage/server_2
	mkdir -p output/server_storage/server_3
	$(CC) examples/hello_world.c -o output/hello_world
	hybolt encode --server-list examples/server_list_example.json --metadata-output output/ output/hello_world
	hybolt decode --server-file examples/server_list_example.json --output-file output/hello_world_decoded output/hello_world_metadata.pkl
	python scripts/compare_files.py output/hello_world output/hello_world_decoded
	chmod +x output/hello_world_decoded
	output/hello_world_decoded
