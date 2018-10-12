docker-images:
	docker build -t patches .
	docker-compose build

unit-test:
	cargo test

integration-test: docker-images
	docker-compose up --abort-on-container-exit

test: integration-test
