use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use axum::serve::Serve;

use http::{Method};
use tower_http::cors::{Any, CorsLayer};

#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age: u8,
}

use crate::privesc::is_local_admin;

use crate::winapi::service::get_services;
use crate::winapi::process::load_processes;
use crate::winapi::tasks::load_tasks;
use crate::winapi::ad::query_users;

pub async fn run_http_server() {

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any);

    let app = Router::new()
        .route("/services", get(|| async {
            let services = get_services();
            Json(services)
        }))
        .route("/is_local_admin", get(|| async {
            let f = is_local_admin::run();
            Json(f)
        }))
        .route("/processes", get(|| async {
            let processes = load_processes();
            Json(processes)
        }))
        .route("/tasks", get(|| async {
            let tasks = load_tasks();
            Json(tasks)
        }))
        .route("/users", get(|| async {
            let users = query_users();
            Json(users)
        }))
        .route("/echo", post(|body: Json<User>| async { Json(body.0) }))
        .layer(cors);


    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap()

}
