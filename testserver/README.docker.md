# Docker Image

## Building Locally

```sh
docker build -t vulnerable_bssl .
docker run --rm vulnerable_bssl
```

## Pulling from registry

```sh
docker pull hub.cs.upb.de/snhebrok/vulnerable-bssl/vulnerable_bssl:master
docker run --rm hub.cs.upb.de/snhebrok/vulnerable-bssl/vulnerable_bssl:master
```
