# patches
A fully distributed patch management system

# Testing

To run unit tests, simply run

```
cargo test
```

Patches also features more complex tests that can be run in Docker.

```
docker build -t patches .
docker-compose up --abort-on-container-exit
```
