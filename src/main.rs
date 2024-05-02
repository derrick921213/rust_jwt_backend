use actix_cors::Cors;
use actix_web::{
    cookie::{self, Cookie},
    post, web, App, HttpResponse, HttpServer,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

#[post("/login")]
async fn login(auth_data: web::Json<AuthData>) -> HttpResponse {
    if auth_data.username == "user" && auth_data.password == "password" {
        let expiration = Utc::now() + Duration::hours(24);
        let claims = Claims {
            sub: auth_data.username.clone(),
            exp: expiration.timestamp(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret_key"),
        )
        .unwrap();

        let cookie = Cookie::build("jwt", token)
            .http_only(true)
            // .secure(true) // 确保在开发时禁用，如果不是https环境
            .secure(false) // 确保在开发时禁用，如果不是https环境
            .same_site(cookie::SameSite::Strict)
            .finish();

        HttpResponse::Ok().cookie(cookie).finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(
                Cors::default() // Use Cors middleware
                    .allowed_origin("http://localhost:8080") // Set allowed origin
                    .allowed_methods(vec!["GET", "POST"]) // Set allowed HTTP methods
                    .allowed_headers(vec![
                        // Set allowed headers
                        "Content-Type",
                        "Authorization",
                    ])
                    .supports_credentials() // Enable credentials (cookies)
                    .max_age(3600),
            )
            .service(login)
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}
