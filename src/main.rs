use actix_files::Files;
use actix_identity::Identity;
use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_multipart::Multipart;
use actix_ratelimit::{MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::dev::{Body, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::middleware::errhandlers::{ErrorHandlerResponse, ErrorHandlers};
use actix_web::middleware::Logger;
use actix_web::{delete, error, get, middleware, post, web, App, Error, HttpServer, Result};
use actix_web::{HttpRequest, HttpResponse};
use actix_web_httpauth::middleware::HttpAuthentication;
use async_std::prelude::*;
use futures::{StreamExt, TryStreamExt, AsyncWriteExt};
use std::{collections::HashMap, time::Duration, path::Path, ffi::OsStr};
use web::Payload;
mod auth;
use rand::Rng;
use tera::Tera;
mod id;
use regex;

mod models;
use actix_cors::Cors;
use dotenv;
use lazy_static::lazy_static;
use serde_json::json;
use actix_web::web::Query;
use sanitize_filename::sanitize;

lazy_static! {
    pub static ref BASE_URL: String = std::env::var("BASE_URL").expect("BASE_URL not set");
    pub static ref AUTH_TOKEN: String = std::env::var("AUTH_TOKEN").expect("No AUTH_TOKEN set");

    // TODO: Make this user-specific and changeable from dashboard?
    // Putting this off because too much overhead maintaining a database for four folks
    pub static ref AUTH_USER: String = std::env::var("AUTH_USER").expect("No AUTH_USER set");
    pub static ref AUTH_PASSWORD: String =
        std::env::var("AUTH_PASSWORD").expect("No AUTH_PASSWORD set");
    pub static ref NAME: String = std::env::var("NAME").expect("No NAME set");
}

#[delete("/{token}", wrap = "HttpAuthentication::bearer(auth::validator)")]
async fn delete_file(file: web::Path<String>) -> Result<HttpResponse, Error> {
    let filename = file.into_inner();
    async_std::fs::remove_file(format!("./static/files/{}", filename)).await?;
    Ok(HttpResponse::Ok().json(json!({
        "message": "deleted file"
    })))
}

#[get("/delete/{token}", wrap = "HttpAuthentication::bearer(auth::validator)")]
async fn delete_get(file: web::Path<String>) -> Result<HttpResponse, Error> {
    let filename = file.into_inner();
    async_std::fs::remove_file(format!("./static/files/{}", filename)).await?;
    Ok(HttpResponse::Ok().json(json!({
        "message": "deleted file"
    })))
}

#[get("/login")]
async fn login(
    tmpl: web::Data<tera::Tera>,
    id: Identity,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, Error> {
    let mut login = false;
    let user = match id.identity() {
        Some(_u) => true,
        None => false,
    };
    if !user {
        println!("{:?}", query);
        if let Some(us) = query.get("username") {
            if let Some(pass) = query.get("password") {
                if us.to_string() == *AUTH_USER && pass.to_string() == *AUTH_PASSWORD {
                    id.remember(us.to_string());
                    login = true; // <- remember identity
                };
            };
        };
    } else {
        login = true;
    }
    println!("what");
    println!("{}", login);
    if login {
        Ok(HttpResponse::Found().header("location", "/ui").finish())
    } else {
        let temp = tmpl.render("login.html", &tera::Context::new()).unwrap();
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(temp))
    }
}

#[get("/logout")]
async fn logout(id: Identity) -> HttpResponse {
    id.forget(); // <- remove identity
    HttpResponse::Found().header("location", "/").finish()
}

#[post("/doc", wrap = "HttpAuthentication::bearer(auth::validator)")]
async fn save_file_rest(req: HttpRequest, mut payload: Payload, query: web::Query<HashMap<String, String>>) -> Result<HttpResponse, Error> {
    // This saves literally any file to the root dir.
    // To prevent scuffing of data, extensions in the filename are ignored in favour of one
    // determined via the Content-Type header.
    let fstem;
    if let Some(f_n) = query.get("filename") {
        fstem = Path::new(f_n).file_stem().and_then(OsStr::to_str).unwrap().to_string().replace(" ", "_");
    } else {
        fstem = id::PostId::generate().to_string();
    }
    let header = req.headers().get("Content-Type").ok_or_else(|| actix_web::error::ParseError::Incomplete)?;
    let mimetype = header.to_str().unwrap().replace("image/", "").replace("application/", "").replace("text/", "");
    let file_fmt = match mimetype.as_str() {
        "vnd.oasis.opendocument.text" => "odt".to_string(),
        "vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx".to_string(),
        "msword" => "doc".to_string(),
        _ => mimetype
    };
    let filename = format!("{}.{}", fstem, file_fmt);
    let filepath = format!("./static/files/{}", sanitize_filename::sanitize(&filename));
    let mut f = async_std::fs::File::create(filepath).await?;
    while let Some(chunk) = payload.next().await {
        let data = chunk.unwrap();
        AsyncWriteExt::write_all(&mut f, &data).await?;
    }
    return Ok(HttpResponse::Ok().json(json!({
        "url": format!("{}/docs/{}", *BASE_URL, filename),
        "deletion_url": format!("{}/delete/{}", *BASE_URL, filename)
    })));
}

async fn save_file(mut payload: Multipart) -> Result<HttpResponse, Error> {
    // This works with the web UI, and the bot. This endpoint is reserved for translations
    // There's some response validation here, but stats are stored bot-side.
    // TODO: make stats endpoint, requires another proxy. Lack of hardware prevents this from happening now.
    let mut f_n = "".to_string();
    let mut valid = false;
    let mut filevec = Vec::new();
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_type = field.content_disposition().ok_or_else(|| actix_web::error::ParseError::Incomplete)?;
        println!("{:?}", content_type);
        let filename = content_type.get_filename().ok_or_else(|| actix_web::error::ParseError::Incomplete)?;
        let re = regex::Regex::new(
            r"([a-zA-Z0-9_\-]+)_(AS|BN|BRX|DOI|GU|KA|KS|KOK|MAI|ML|MNI|MR|NE|OR|PA|SA|SAT|SD|TA|TE|UR)\.(pdf|odt|doc|docx)"
        ).unwrap();
        if re.is_match(filename) {
            let filepath = format!("./static/files/{}", sanitize_filename::sanitize(&filename));
            f_n = filename.to_string();
            let mut f = async_std::fs::File::create(filepath).await?;
            while let Some(chunk) = field.next().await {
                let data = chunk.unwrap();
                AsyncWriteExt::write_all(&mut f, &data).await?;
            }
            filevec.push(json!({
                "url": format!("{}/docs/{}", *BASE_URL, f_n),
                "deletion_url": format!("{}/delete/{}", *BASE_URL, f_n)
            }));
            valid = true;
        } else {
            valid = false;
        }
    }

    if valid {
        Ok(HttpResponse::Ok().json(json!({ "files": filevec })))
    } else {
        Ok(HttpResponse::BadRequest().json(json!({
            "message": "Bad filename. Refer spec."
        })))
    }
}

#[get("/")]
async fn index(tmpl: web::Data<tera::Tera>) -> Result<HttpResponse, Error> {
    let temp = tmpl.render("index.html", &tera::Context::new()).unwrap();
    Ok(HttpResponse::Ok().content_type("text/html; charset=utf-8").body(temp))
}

#[get("/ui")]
async fn upload_ui(tmpl: web::Data<tera::Tera>, id: Identity) -> Result<HttpResponse, Error> {
    println!("{:?}", id.identity());
    let user = match id.identity() {
        Some(_u) => true,
        None => false,
    };
    println!("{}", user);
    if user {
        let temp = tmpl.render("upload.html", &tera::Context::new())
            .map_err(|_| error::ErrorInternalServerError("Template error!"))?;
        Ok(HttpResponse::Ok().content_type("text/html; charset=utf-8").body(temp))
    } else {
        Ok(HttpResponse::Found().header("location", "/login").finish())
    }
}

fn error_handlers() -> ErrorHandlers<Body> {
    ErrorHandlers::new().handler(StatusCode::METHOD_NOT_ALLOWED, method_not_allowed)
        .handler(StatusCode::NOT_FOUND, not_found)
        .handler(StatusCode::INTERNAL_SERVER_ERROR, internal_server_error)
        .handler(StatusCode::UNAUTHORIZED, unauthorised_or_forbidden)
        .handler(StatusCode::FORBIDDEN, unauthorised_or_forbidden)
}

fn not_found<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let html = include_str!("../templates/404.html").to_string();
    Ok(ErrorHandlerResponse::Response(
        res.into_response(
            HttpResponse::NotFound().content_type("text/html; charset=utf-8")
                .body(html).into_body(),
        ),
    ))
}

fn method_not_allowed<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let resa = res.request().clone();
    Ok(ErrorHandlerResponse::Response(
        res.into_response(
            HttpResponse::MethodNotAllowed()
                .json(json!({
                    "message": format!("{} is not allowed for url {}", resa.method().to_string(), resa.uri().to_string())
                }))
                .into_body(),
        ),
    ))
}

fn internal_server_error<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let html = include_str!("../templates/50x.html").to_string();
    Ok(ErrorHandlerResponse::Response(
        res.into_response(
            HttpResponse::InternalServerError().content_type("text/html; charset=utf-8")
                .body(html).into_body(),
        ),
    ))
}

fn unauthorised_or_forbidden<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let html = include_str!("../templates/403.html").to_string();
    Ok(ErrorHandlerResponse::Response(
        res.into_response(
            HttpResponse::Forbidden().content_type("text/html; charset=utf8")
                .body(html).into_body(),
        ),
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    std::env::set_var("RUST_BACKTRACE", "1");
    println!("Loading Env vars");
    dotenv::dotenv().ok();
    println!("Starting server....");

    let start = std::env::var("URL").expect("Need a URL bob");
    let port = std::env::var("PORT").expect("Need a port bob");
    env_logger::init();
    HttpServer::new(|| {
        let tera = Tera::new("templates/**/**").unwrap();
        let store = MemoryStore::new();
        let auth_conf = models::Auth {
            user: AUTH_USER.as_str().to_string(),
            password: AUTH_PASSWORD.as_str().to_string(),
        };
        let protect_form = Cors::default().allowed_origin(&BASE_URL);
        let private_key = rand::thread_rng().gen::<[u8; 32]>();
        println!("Data ready");
        App::new()
            .data(tera)
            .wrap(middleware::Compress::default())
            .service(Files::new("/docs", "static/files"))
            .service(Files::new("/assets", "assets"))
            .wrap(
                RateLimiter::new(MemoryStoreActor::from(store.clone()).start())
                    .with_interval(Duration::from_secs(60))
                    .with_max_requests(30),
            )
            .data(auth_conf)
            .service(index)
            .service(
                web::resource("/ui/upload")
                    .route(web::post().to(save_file))
                    .wrap(protect_form),
            )
            .service(upload_ui)
            .service(save_file_rest)
            .service(delete_file)
            .service(delete_get)
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&private_key)
                    .name("cdn")
                    .secure(false),
            ))
            .service(
                web::resource("/upload")
                    .route(web::post().to(save_file))
                    .wrap(HttpAuthentication::bearer(auth::validator)),
            )
            .service(login)
            .service(logout)
            .service(web::scope("").wrap(error_handlers()))
            .wrap(Logger::default())
    })
        .workers(1)
        .bind(format!("{}:{}", start, port))
        .unwrap()
        .run()
        .await
}