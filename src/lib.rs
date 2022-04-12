use crate::mux_webhook_event::{MuxEvent, MuxWebhookEvent};
use crate::telegram_client::TelegramClient;

use serde::Serialize;
use worker::*;

mod crypto;
mod mux_webhook_event;
mod telegram_client;
mod utils;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or_else(|| "unknown region".into())
    );
}

#[derive(Serialize)]
struct MuxEventReport {
    data: MuxEvent,
    verified: bool,
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let router = Router::new();
    router
        .post_async("/mux-endpoint", |mut req, ctx| async move {
            let mux_secret = ctx.var("MUX_WEBHOOK_SIGNING_SECRET")?.to_string();
            let mux_webhook_event = MuxWebhookEvent::new(&mux_secret);
            let mux_signature = match req.headers().get("Mux-Signature").unwrap() {
                Some(value) => value,
                None => return Response::error("Bad request", 400),
            };
            let raw_request_body = match req.text().await {
                Ok(res) => res,
                Err(_) => return Response::error("Bad request", 400),
            };
            let data: MuxEvent = match serde_json::from_str(&raw_request_body) {
                Ok(res) => res,
                Err(_) => return Response::error("Bad request", 400),
            };
            let verified: bool = mux_webhook_event.verify_event(&mux_signature, &raw_request_body);
            let report: MuxEventReport = MuxEventReport { data, verified };
            let telegram_message = serde_json::to_string_pretty(&report).unwrap();
            let telegram_bot_api_token = ctx.var("TELEGRAM_BOT_API_TOKEN")?.to_string();
            let telegram_bot_chat_id = ctx.var("TELEGRAM_BOT_CHAT_ID")?.to_string();
            let telegram_client =
                TelegramClient::new(&telegram_bot_api_token, &telegram_bot_chat_id, None);
            telegram_client.send_message(&telegram_message).await;
            Response::ok("Received loud and clear!")
        })
        .run(req, env)
        .await
}
