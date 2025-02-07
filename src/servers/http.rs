use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use axum::serve::Serve;


#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age: u8,
}

use crate::winapi::service::get_services;

pub async fn run_http_server() {

    let app = Router::new()
        .route("/services", get(|| async {
            let services = get_services();
            Json(services)
        }))
        .route("/echo", post(|body: Json<User>| async { Json(body.0) }));


    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap()

}
