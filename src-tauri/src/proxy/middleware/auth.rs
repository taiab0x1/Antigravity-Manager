// API Key 认证中间件
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::proxy::{ProxyAuthMode, ProxySecurityConfig};

/// API Key 认证中间件 (代理接口使用，遵循 auth_mode)
pub async fn auth_middleware(
    state: State<Arc<RwLock<ProxySecurityConfig>>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    auth_middleware_internal(state, request, next, false).await
}

/// 管理接口认证中间件 (管理接口使用，强制严格鉴权)
pub async fn admin_auth_middleware(
    state: State<Arc<RwLock<ProxySecurityConfig>>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    auth_middleware_internal(state, request, next, true).await
}

/// 内部认证逻辑
async fn auth_middleware_internal(
    State(security): State<Arc<RwLock<ProxySecurityConfig>>>,
    request: Request,
    next: Next,
    force_strict: bool,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // 过滤心跳和健康检查请求,避免日志噪音
    let is_health_check = path == "/healthz" || path == "/api/health" || path == "/health";
    let is_internal_endpoint = path.starts_with("/internal/");
    if !path.contains("event_logging") && !is_health_check {
        tracing::info!("Request: {} {}", method, path);
    } else {
        tracing::trace!("Heartbeat/Health: {} {}", method, path);
    }

    // Allow CORS preflight regardless of auth policy.
    if method == axum::http::Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let security = security.read().await.clone();
    let effective_mode = security.effective_auth_mode();

    // 权限检查逻辑
    if should_bypass_auth(
        force_strict,
        &effective_mode,
        is_health_check,
        is_internal_endpoint,
    ) {
        return Ok(next.run(request).await);
    }

    if !force_strict {
        // AI 代理接口 (v1/chat/completions 等)
        if matches!(effective_mode, ProxyAuthMode::Off) {
            // [FIX] 即使 auth_mode=Off，也需要尝试识别 User Token 以记录使用情况
            // 先检查是否携带了 User Token
            let api_key = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").or(Some(s)))
                .or_else(|| {
                    request
                        .headers()
                        .get("x-api-key")
                        .and_then(|h| h.to_str().ok())
                });

            if let Some(token) = api_key {
                // 尝试验证是否为 User Token（不阻止请求，只记录）
                if let Ok(Some(user_token)) =
                    crate::modules::user_token_db::get_token_by_value(token)
                {
                    let identity = UserTokenIdentity {
                        token_id: user_token.id,
                        token: user_token.token,
                        username: user_token.username,
                    };
                    // 注入 identity 到请求
                    let (mut parts, body) = request.into_parts();
                    parts.extensions.insert(identity);
                    let request = Request::from_parts(parts, body);
                    return Ok(next.run(request).await);
                }
            }

            return Ok(next.run(request).await);
        }
    }

    // 从 header 中提取 API key
    let api_key = extract_api_key(request.headers());

    if force_strict {
        if !has_admin_credentials(&security) {
            tracing::error!(
                "Admin auth is required but both api_key and admin_password are empty; denying request"
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else if security.api_key.is_empty() {
        tracing::error!("Proxy auth is enabled but api_key is empty; denying request");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 认证逻辑
    let authorized = if force_strict {
        // 管理接口：优先使用独立的 admin_password，如果没有则回退使用 api_key
        is_admin_authorized(&security, api_key)
    } else {
        // AI 代理接口：仅允许使用 api_key
        api_key.map(|k| k == security.api_key).unwrap_or(false)
    };

    if authorized {
        Ok(next.run(request).await)
    } else if !force_strict && api_key.is_some() {
        // 尝试验证 UserToken
        let token = api_key.unwrap();

        // 提取 IP (复用逻辑)
        let client_ip = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "127.0.0.1".to_string()); // Default fallback

        // 验证 Token
        match crate::modules::user_token_db::validate_token(token, &client_ip) {
            Ok((true, _)) => {
                // Token 有效，查询信息以便传递
                if let Ok(Some(user_token)) =
                    crate::modules::user_token_db::get_token_by_value(token)
                {
                    let identity = UserTokenIdentity {
                        token_id: user_token.id,
                        token: user_token.token,
                        username: user_token.username,
                    };

                    // [FIX] 将身份信息注入到请求 extensions 中，而不是响应
                    // 这样 monitor_middleware 在处理请求时就能获取到 identity
                    // 因为中间件执行顺序：auth (外层) -> monitor (内层) -> handler
                    // 响应返回时：handler -> monitor -> auth
                    // 如果注入到 response，monitor 执行时 identity 还不存在
                    let (mut parts, body) = request.into_parts();
                    parts.extensions.insert(identity);
                    let request = Request::from_parts(parts, body);

                    // 执行请求
                    let response = next.run(request).await;

                    Ok(response)
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
            Ok((false, reason)) => {
                let reason_str = reason.unwrap_or_else(|| "Access denied".to_string());
                tracing::warn!("UserToken rejected: {}", reason_str);
                let body = serde_json::json!({
                    "error": {
                        "message": reason_str,
                        "type": "token_rejected",
                        "code": "token_rejected"
                    }
                });
                let response = axum::response::Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(&body).unwrap(),
                    ))
                    .unwrap();
                Ok(response)
            }
            Err(e) => {
                tracing::error!("UserToken validation error: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn should_bypass_auth(
    force_strict: bool,
    effective_mode: &ProxyAuthMode,
    is_health_check: bool,
    is_internal_endpoint: bool,
) -> bool {
    if force_strict {
        // 管理接口必须始终强制鉴权；只允许健康检查无鉴权通过。
        return is_health_check;
    }

    matches!(effective_mode, ProxyAuthMode::AllExceptHealth) && is_health_check
        || is_internal_endpoint
}

fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or(Some(s)))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))
        .or_else(|| headers.get("x-goog-api-key").and_then(|h| h.to_str().ok()))
}

fn has_admin_credentials(security: &ProxySecurityConfig) -> bool {
    !security.api_key.is_empty()
        || security
            .admin_password
            .as_ref()
            .map(|password| !password.is_empty())
            .unwrap_or(false)
}

fn is_admin_authorized(security: &ProxySecurityConfig, api_key: Option<&str>) -> bool {
    match &security.admin_password {
        Some(password) if !password.is_empty() => api_key.map(|k| k == password).unwrap_or(false),
        _ => api_key.map(|k| k == security.api_key).unwrap_or(false),
    }
}

/// 用户令牌身份信息 (传递给 Monitor 使用)
#[derive(Clone, Debug)]
pub struct UserTokenIdentity {
    pub token_id: String,
    #[allow(dead_code)] // 保留原始 token 便于审计/调试
    pub token: String,
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyAuthMode;

    fn security_config(
        auth_mode: ProxyAuthMode,
        allow_lan_access: bool,
        api_key: &str,
        admin_password: Option<&str>,
    ) -> ProxySecurityConfig {
        ProxySecurityConfig {
            auth_mode,
            api_key: api_key.to_string(),
            admin_password: admin_password.map(str::to_string),
            allow_lan_access,
            port: 8045,
            security_monitor: crate::proxy::config::SecurityMonitorConfig::default(),
        }
    }

    #[test]
    fn admin_auth_does_not_bypass_when_auto_local_resolves_off() {
        let security = security_config(ProxyAuthMode::Auto, false, "sk-api", None);
        let effective_mode = security.effective_auth_mode();

        assert!(matches!(effective_mode, ProxyAuthMode::Off));
        assert!(!should_bypass_auth(false, &effective_mode, false, false));
        assert!(!should_bypass_auth(true, &effective_mode, false, false));
        assert!(should_bypass_auth(true, &effective_mode, true, false));
    }

    #[test]
    fn proxy_auth_still_bypasses_internal_routes() {
        let security = security_config(ProxyAuthMode::Strict, true, "sk-api", None);
        let effective_mode = security.effective_auth_mode();

        assert!(should_bypass_auth(false, &effective_mode, false, true));
        assert!(!should_bypass_auth(true, &effective_mode, false, true));
    }

    #[test]
    fn admin_auth_prefers_admin_password_over_api_key() {
        let security = security_config(ProxyAuthMode::Off, false, "sk-api", Some("admin123"));

        assert!(has_admin_credentials(&security));
        assert!(is_admin_authorized(&security, Some("admin123")));
        assert!(!is_admin_authorized(&security, Some("sk-api")));
        assert!(!is_admin_authorized(&security, None));
    }

    #[test]
    fn admin_auth_falls_back_to_api_key_without_admin_password() {
        let security = security_config(ProxyAuthMode::Off, false, "sk-api", None);

        assert!(has_admin_credentials(&security));
        assert!(is_admin_authorized(&security, Some("sk-api")));
        assert!(!is_admin_authorized(&security, Some("wrong")));
    }

    #[test]
    fn admin_auth_requires_some_configured_secret() {
        let security = security_config(ProxyAuthMode::Off, false, "", None);

        assert!(!has_admin_credentials(&security));
        assert!(!is_admin_authorized(&security, Some("")));
    }

    #[test]
    fn api_key_extraction_supports_expected_headers() {
        let bearer = Request::builder()
            .header("Authorization", "Bearer admin123")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_api_key(bearer.headers()), Some("admin123"));

        let x_api_key = Request::builder()
            .header("x-api-key", "sk-api")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_api_key(x_api_key.headers()), Some("sk-api"));

        let google_key = Request::builder()
            .header("x-goog-api-key", "google-key")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_api_key(google_key.headers()), Some("google-key"));
    }
}
