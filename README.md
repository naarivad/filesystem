# Document Uploader
Robust document uploader and filesystem-over-HTTP implementation.

## Features
- Web UI with login
- Simple HTTP upload interface
- Upload endpoint that supports forms
- Automatic file compression
- Speed and Efficiency (well it's Rust)

## Env file

To run this, you need all config vars set as env vars.
A `.env` file in the same directory is automatically sourced.
If there is none, global env vars are sourced.

```dotenv
BASE_URL="https://test.mydomain.tld"
AUTH_TOKEN="secure string for REST API requests"
AUTH_USER="noobmaster69"
AUTH_PASSWORD="iloveyou3000"
NAME="something amazing, I guess"
URL="0.0.0.0"
PORT="3000"  # Or whatever
```

## Running in Docker

Simple single line Docker command:

```shell
docker run -d -V ./static:/usr/local/bin/static -p 3000:3000 --expose 3000 --env-file .env ghcr.io/naarivad/filesystem
```

And there, you have a running instance.

The image doesn't support ARM so if you want to run on a Raspberry Pi, say, you can use the binaries instead.

## Running the binaries

1) Choose the architecture. These should be in the relases
2) Download the file (`wget`, `curl`) based on the architecture
3) Extract the `*.tar.gz` file and `cd` into the folder
4) Create the `.env` file with the config vars
5) `./filesystem` and look for any logs!

## License
[BSD-3-Clause](LICENSE) &copy; Varun J &lt;root@varunj.me&gt;

## Contributing

Fork and run with Cargo. For Docker testing there's a `dev.Dockerfile` that uses cargo chef.
Cargo chef instructions are given below.

```shell
cargo install cargo-chef
cargo chef prepare --recipe-path recipe.json
```

## Issues/bugs

Create an issue. If I don't respond within 48 hours, shoot me an email.

## TODO

- [x] Dockerise
- [x] Publish binaries for different os arch
- [ ] Stats endpoint for translation metrics (currently handled by discord bot)
- [ ] Better login form with per-user passwords, changeable from dashboard (low priority)
- [ ] Better UX on error responses on upload (very low priority. only admins see it anyway)
