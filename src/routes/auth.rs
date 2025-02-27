use actix_web::{web, HttpResponse, Responder};

pub async fn login(
    req: web::Json<LoginRequest>,
    auth_service: web::Data<AuthService>,
    session_service: web::Data<SessionService>,
    request: HttpRequest,
) -> Result<impl Responder, Error> {
    let user = match auth_service
        .authenticate(&req.username, &req.password)
        .await?
    {
        Some(user) => user,
        None => return Ok(HttpResponse::Unauthorized().finish()),
    };

    let session = session_service.create_session(&user, &request).await?;

    Ok(HttpResponse::Ok().json(json!({
        "token": session.token,
        "csrf_token": session.csrf_token,
    })))
}
