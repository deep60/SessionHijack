use axum::{
    extract::{Form, State},
    response::{Html, Redirect},
    routing::{get, post},
    Router,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

#[derive(Clone)]
struct AppState {
    users: Arc<Mutex<HashMap<String, String>>>,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(login_page))
        .route("/login", post(handle_login))
        .route("/dashboard", get(dashboard))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    println!("Server running at http://127.0.0.1:3000");
    axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn login_page() -> Html<&'static str> {
    Html(
        r#"
        <form action="/login" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        "#,
    )
}

async fn handle_login(
    Form(data): Form<HashMap<String, String>>,
    State(state): State<AppState>,
    cookies: Cookies,
) -> Redirect {
    let users = state.users.lock().await;
    let username = data.get("username").unwrap_or(&"".to_string()).clone();
    let password = data.get("password").unwrap_or(&"".to_string()).clone();

    if users.get(&username) == Some(&password) {
        let session_token = format!("session-{}", rand::random::<u64>());
        cookies.add(
            Cookie::build("session_id", session_token)
                .secure(true)
                .http_only(true),
        );
        Redirect::to("/dashboard")
    } else {
        ReadDirect::to("/")
    }
}

async fn dashboard(cookies: Cookies) -> Html<String> {
    if let Some(cookie) = cookies.get("session-id") {
        Html(format!("Welcome! Your session: {}", cookie.value()))
    } else {
        Html("Unauthorized! <a href='/'>Login</a>".to_string())
    }
}
