use serde_json::Value;

pub fn canonicalize(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(value)
        .map_err(|e| serde_json::Error::io(std::io::Error::other(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_and_strips_whitespace() {
        let value = json!({"b": 1, "a": [2, {"z": true, "y": null}], "c": "x"});
        assert_eq!(
            String::from_utf8(canonicalize(&value).unwrap()).unwrap(),
            r#"{"a":[2,{"y":null,"z":true}],"b":1,"c":"x"}"#
        );
    }

    #[test]
    fn canonical_output_is_deterministic() {
        let first = json!({"issuer": "did:key:z6Mk", "n": 3});
        let second = json!({"n": 3, "issuer": "did:key:z6Mk"});
        assert_eq!(
            canonicalize(&first).unwrap(),
            canonicalize(&second).unwrap()
        );
    }

    #[test]
    fn formats_numbers_like_ecmascript_per_rfc8785() {
        let value = json!({"float": 1.0, "int": 10});
        let rendered = String::from_utf8(canonicalize(&value).unwrap()).unwrap();
        assert_eq!(rendered, r#"{"float":1,"int":10}"#);
    }
}
