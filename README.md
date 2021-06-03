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

## License
[AGPL v3.0](LICENSE) &copy; Varun J <root@varunj.me>

## Contributing

Fork and run with Cargo

## Issues/bugs

Create an issue. If I don't respond within 48 hours, shoot me an email.

## TODO

- [ ] Dockerise
- [ ] Publish binaries for different os arch
- [ ] Stats endpoint for translation metrics (currently handled by discord bot)
- [ ] Better login form with per-user passwords, changeable from dashboard (low priority)
- [ ] Better UX on error responses on upload (very low priority. only admins see it anyway)