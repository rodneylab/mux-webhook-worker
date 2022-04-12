use crate::crypto::hmac_sha_256_verify;
use nom::{
    bytes::complete::tag,
    character::complete::{alphanumeric1, char, hex_digit1},
    sequence::separated_pair,
    IResult,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct MuxPlaybackId {
    policy: String,
    id: String,
}

#[derive(Deserialize, Serialize)]
struct MuxData {
    status: String,
    playback_ids: Vec<MuxPlaybackId>,
    id: String,
    duration: Option<f32>,
    created_at: u32,
    aspect_ratio: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct MuxEvent {
    r#type: String,
    data: MuxData,
    id: String,
    created_at: String,
}

pub struct MuxWebhookEvent {
    signing_secret: String,
}

impl MuxWebhookEvent {
    pub fn new(signing_secret: &str) -> MuxWebhookEvent {
        MuxWebhookEvent {
            signing_secret: signing_secret.into(),
        }
    }

    #[allow(dead_code)]
    pub fn parse_mux_signature_header(mux_signature: &str) -> IResult<&str, (&str, &str)> {
        let mut parser = separated_pair(
            nom::sequence::preceded(tag("t="), alphanumeric1),
            char(','),
            nom::sequence::preceded(tag("v1="), hex_digit1),
        );
        parser(mux_signature)
    }

    #[allow(dead_code)]
    pub fn verify_event(&self, mux_signature: &str, raw_request_body: &str) -> bool {
        let (timestamp, signature) =
            match MuxWebhookEvent::parse_mux_signature_header(mux_signature) {
                Ok((_, (val_timestamp, val_signature))) => (val_timestamp, val_signature),
                Err(_) => return false,
            };
        let payload = format!("{}.{}", timestamp, raw_request_body);
        hmac_sha_256_verify(
            self.signing_secret.as_bytes(),
            payload.as_bytes(),
            &hex::decode(signature).unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::MuxEvent;
    use crate::MuxWebhookEvent;
    #[test]
    pub fn test_parse_mux_signature_header() {
        let mux_signature =
            "t=1565125718,v1=854ece4c22acef7c66b57d4e504153bc512595e8e9c772ece2a68150548c19a7";
        assert_eq!(
            MuxWebhookEvent::parse_mux_signature_header(&mux_signature),
            Ok((
                "",
                (
                    "1565125718",
                    "854ece4c22acef7c66b57d4e504153bc512595e8e9c772ece2a68150548c19a7"
                )
            ))
        );
    }

    #[test]
    pub fn test_verify_event() {
        // fixtures from mux repo tests: https://github.com/muxinc/mux-node-sdk/blob/master/test/unit/webhooks/resources/verify_header.spec.js
        let signing_secret = "SuperSecret123";
        let mux_webhook_event = MuxWebhookEvent::new(&signing_secret);
        let mux_signature =
            "t=1565125718,v1=854ece4c22acef7c66b57d4e504153bc512595e8e9c772ece2a68150548c19a7";
        let raw_request_body = "{\"test\":\"body\"}";
        assert!(mux_webhook_event.verify_event(mux_signature, raw_request_body));
    }

    #[test]
    pub fn test_mux_event_data_structure() -> Result<(), serde_json::Error> {
        let created_raw_request_body = "{\"type\":\"video.asset.created\",\"request_id\":null,\"object\":{\"type\":\"asset\",\"id\":\"8QNt802sz70q1HpothohoAJNW01SxvbWRCizu5qB6z6gM\"},\"id\":\"a58b4ba9-284d-40e5-aa2e-8b557ca875d0\",\"environment\":{\"name\":\"Production\",\"id\":\"nf29e9\"},\"data\":{\"status\":\"preparing\",\"playback_ids\":[{\"policy\":\"public\",\"id\":\"eSlnicVTAEOq23cx5rrsKYoZEKLu00diJW1H37NEjrs8\"}],\"mp4_support\":\"standard\",\"master_access\":\"none\",\"id\":\"8QNt802sz13q1HpowhohoAJQu91SxvbWRCizu5qB4z6gM\",\"created_at\":1649777509},\"created_at\":\"2022-04-12T15:31:50.000000Z\",\"attempts\":[{\"webhook_id\":12345,\"response_status_code\":400,\"response_headers\":{\"date\":\"Tue,12Apr202215:31:51GMT\",\"content-length\":\"13\"},\"response_body\":\"Badrequest\",\"max_attempts\":30,\"id\":\"995f1e26-5164-40f9-8b74-972d8aaab5c7\",\"created_at\":\"2022-04-12T15:31:51.000000Z\",\"address\":\"https://example.com/mux-example-endpoint\"}],\"accessor_source\":null,\"accessor\":null}";
        let _data: MuxEvent = serde_json::from_str(&created_raw_request_body).unwrap();

        let ready_raw_request_body = "{\"type\":\"video.asset.static_renditions.ready\",\"request_id\":null,\"object\":{\"type\":\"asset\",\"id\":\"6DK2ysIoRrRK21bR11iwbZbfAr4Dcc6d00P2wBJsRcSM\"},\"id\":\"eb5fd989-acd0-456f-9acf-87b79435e320\",\"environment\":{\"name\":\"Production\",\"id\":\"nf29e9\"},\"data\":{\"tracks\":[{\"type\":\"video\",\"max_width\":1848,\"max_height\":1040,\"max_frame_rate\":29.87,\"id\":\"QEz02bRdtW1m2yWyXq02SeLS4lUe5oVRLNhdsDWpxfMGQ\",\"duration\":7.331733},{\"type\":\"audio\",\"max_channels\":2,\"max_channel_layout\":\"stereo\",\"id\":\"mJV2z6wvS7vSHSp4ijt01V3ApsXUGsL4pFqpO9HJ9364\",\"duration\":7.337333},{\"type\":\"text\",\"text_type\":\"subtitles\",\"text_source\":\"uploaded\",\"status\":\"ready\",\"name\":\"English\",\"language_code\":\"en-GB\",\"id\":\"1VOe7U2XGEsYrQF2z76IP74KEZE6cBwdRrcOM00VLrasJR915VkYAQg\",\"closed_captions\":true}],\"status\":\"ready\",\"static_renditions\":{\"status\":\"ready\",\"files\":[{\"width\":640,\"name\":\"low.mp4\",\"height\":360,\"filesize\":218013,\"ext\":\"mp4\",\"bitrate\":235752},{\"width\":960,\"name\":\"medium.mp4\",\"height\":540,\"filesize\":280599,\"ext\":\"mp4\",\"bitrate\":303432},{\"width\":1848,\"name\":\"high.mp4\",\"height\":1040,\"filesize\":456232,\"ext\":\"mp4\",\"bitrate\":493352}]},\"playback_ids\":[{\"policy\":\"public\",\"id\":\"buwMQjHrW24zlt3COatm35kUeNfQOULYwhGQGY12wv8\"}],\"mp4_support\":\"standard\",\"max_stored_resolution\":\"HD\",\"max_stored_frame_rate\":29.87,\"master_access\":\"none\",\"id\":\"6DK2ysIoRrRK21bR11iwbZbfAr4Dcc6d00P2wBJsRcSM\",\"duration\":7.399744,\"created_at\":1649776630,\"aspect_ratio\":\"231:130\"},\"created_at\":\"2022-04-12T15:17:26.000000Z\",\"attempts\":[],\"accessor_source\":null,\"accessor\":null}";
        let _data: MuxEvent = serde_json::from_str(&ready_raw_request_body).unwrap();

        Ok(())
    }
}
