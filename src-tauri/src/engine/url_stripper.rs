use std::borrow::Cow;
use url::Url;

static PROTECTED_PARAMS: &[&str] = &[
    "sid",
    "session",
    "session_id",
    "sessionid",
    "auth",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "nonce",
    "state", // OAuth2 CSRF state — must be preserved
    "code",  // OAuth2 authorisation code
    "oauth_token",
    "csrf",
    "csrf_token",
    "_token",
    "xsrf_token",
];

static STRIP_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_source_platform",
    "utm_creative_format",
    "utm_marketing_tactic",
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "_ga",
    "_gl",
    "gad_source",
    "fbclid",
    "fb_action_ids",
    "fb_action_types",
    "fb_source",
    "fb_ref",
    "fbid",
    "msclkid",
    "twclid",
    "s_kwcid",
    "ttclid",
    "ScCid",
    "li_fat_id",
    "li_source",
    "epik",
    "_hsenc",
    "_hsmi",
    "hsa_acc",
    "hsa_ad",
    "hsa_cam",
    "hsa_grp",
    "hsa_kw",
    "hsa_la",
    "hsa_mt",
    "hsa_net",
    "hsa_src",
    "hsa_tgt",
    "hsa_ver",
    "mc_eid",
    "mc_cid",
    "vero_id",
    "vero_conv",
    "mkt_tok",
    "iterableEmailCampaignId",
    "iterableTemplateId",
    "iterableMessageId",
    "_kx",
    "sg_uid",
    "sg_mid",
    "tag", // Amazon affiliate tag (note: also used by some non-trackers; see prefix rule below)
    "psc",
    "smid",
    "obOrigUrl",
    "tblci",
    "click_id",
    "clickid",
    "cid", // generic campaign ID (not session ID)
    "icid",
    "ncid",
    "ocid",
    "yclid", // Yandex
    "wickedid",
    "irclickid", // Impact Radius
    "sref",
    "otc",
    "referrer", // plain "referrer" param (not the Referer header)
    "ref_src",
    "ref_url",
];

static STRIP_PREFIXES: &[&str] = &["utm_", "hsa_", "fb_", "ga_", "iterable"];

/// Strip known tracking parameters from a URL string.
/// Returns the cleaned URL. If parsing fails, the original string is returned.
pub fn strip(raw_url: &str) -> Cow<str> {
    let Ok(mut url) = Url::parse(raw_url) else {
        return Cow::Borrowed(raw_url);
    };

    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| !should_strip(k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let original_count = url.query_pairs().count();
    if pairs.len() == original_count {
        return Cow::Owned(raw_url.to_string());
    }

    if pairs.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(&pairs);
    }

    Cow::Owned(url.to_string())
}

/// Returns true if the parameter should be stripped.
fn should_strip(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();

    if PROTECTED_PARAMS.iter().any(|p| lower == *p) {
        return false;
    }

    if STRIP_PARAMS.iter().any(|p| lower == *p) {
        return true;
    }

    if STRIP_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_utm_params() {
        let input = "https://example.com/page?utm_source=twitter&utm_campaign=launch&q=rust";
        let out = strip(input);
        assert!(out.contains("q=rust"), "functional param preserved");
        assert!(!out.contains("utm_source"), "utm_source stripped");
        assert!(!out.contains("utm_campaign"), "utm_campaign stripped");
    }

    #[test]
    fn preserves_session_params() {
        let input = "https://example.com/login?session_id=abc123&fbclid=XYZ";
        let out = strip(input);
        assert!(out.contains("session_id=abc123"), "session_id protected");
        assert!(!out.contains("fbclid"), "fbclid stripped");
    }

    #[test]
    fn preserves_oauth_state() {
        let input = "https://auth.example.com/callback?code=AUTH_CODE&state=CSRF_STATE&fbclid=X";
        let out = strip(input);
        assert!(out.contains("code=AUTH_CODE"), "OAuth code protected");
        assert!(out.contains("state=CSRF_STATE"), "OAuth state protected");
        assert!(!out.contains("fbclid"), "fbclid stripped");
    }

    #[test]
    fn no_change_on_clean_url() {
        let input = "https://example.com/page?q=hello&page=2";
        let out = strip(input);
        assert_eq!(out.as_ref(), input);
    }

    #[test]
    fn handles_unparseable_url() {
        let input = "not a url at all";
        let out = strip(input);
        assert_eq!(out.as_ref(), input);
    }

    #[test]
    fn strips_gclid_and_fbclid() {
        let input = "https://shop.example.com/item?id=42&gclid=Cj0K&fbclid=IwAR&color=red";
        let out = strip(input);
        assert!(out.contains("id=42"), "functional id kept");
        assert!(out.contains("color=red"), "functional color kept");
        assert!(!out.contains("gclid"), "gclid stripped");
        assert!(!out.contains("fbclid"), "fbclid stripped");
    }

    #[test]
    fn strips_custom_prefix() {
        let input = "https://example.com/?hsa_acc=123&hsa_net=adwords&q=test";
        let out = strip(input);
        assert!(out.contains("q=test"));
        assert!(!out.contains("hsa_acc"));
        assert!(!out.contains("hsa_net"));
    }
}
