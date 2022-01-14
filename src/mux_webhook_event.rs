use nom::{
    bytes::complete::tag,
    character::complete::{alphanumeric1, char, hex_digit1},
    sequence::separated_pair,
    IResult,
};

use crate::crypto::hmac_sha_256_verify;

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
        // let raw_request_body = "{ \"type\": \"video.asset.ready\", \"object\": { \"type\": \"asset\", \"id\": \"0201p02fGKPE7MrbC269XRD7LpcHhrmbu0002\" }, \"id\": \"3a56ac3d-33da-4366-855b-f592d898409d\", \"environment\": { \"name\": \"Demo pages\", \"id\": \"j0863n\" }, \"data\": { \"tracks\": [ { \"type\": \"video\", \"max_width\": 1280, \"max_height\": 544, \"max_frame_rate\": 23.976, \"id\": \"0201p02fGKPE7MrbC269XRD7LpcHhrmbu0002\", \"duration\": 153.361542 }, { \"type\": \"audio\", \"max_channels\": 2, \"max_channel_layout\": \"stereo\", \"id\": \"FzB95vBizv02bYNqO5QVzNWRrVo5SnQju\", \"duration\": 153.361497 } ], \"status\": \"ready\", \"max_stored_resolution\": \"SD\", \"max_stored_frame_rate\": 23.976, \"id\": \"0201p02fGKPE7MrbC269XRD7LpcHhrmbu0002\", \"duration\": 153.361542, \"created_at\": \"2018-02-15T01:04:45.000Z\", \"aspect_ratio\": \"40:17\" }, \"created_at\": \"2018-02-15T01:04:45.000Z\", \"accessor_source\": null, \"accessor\": null, \"request_id\": null }";
        assert!(mux_webhook_event.verify_event(mux_signature, raw_request_body));
    }
}
