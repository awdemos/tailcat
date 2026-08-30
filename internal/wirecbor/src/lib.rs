// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::slice;

/// Maximum CBOR input size accepted by the decoder, in bytes. This bounds the
/// work done on untrusted tokens.
const MAX_CBOR_LEN: usize = 64 * 1024;

/// JSON bridge type for the Go side. ServerPublic is transferred as a hex
/// string because the Go encoding/json package for [32]u8 produces a base64
/// string while serde_json for Vec<u8> produces an integer array; hex is
/// unambiguous and trivial to implement in both languages.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ConnInfo {
    #[serde(with = "hexserde")]
    #[serde(rename = "ServerPublic")]
    server_public: Vec<u8>,
    #[serde(rename = "Region")]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    region: Vec<Region>,
    #[serde(rename = "RegionID")]
    #[serde(skip_serializing_if = "is_zero", default)]
    region_id: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Region {
    #[serde(rename = "RegionID")]
    #[serde(skip_serializing_if = "is_zero", default)]
    region_id: i64,
    #[serde(rename = "RegionCode")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    region_code: String,
    #[serde(rename = "RegionName")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    region_name: String,
    #[serde(rename = "Nodes")]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    nodes: Vec<Node>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Node {
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    name: String,
    #[serde(rename = "RegionID")]
    #[serde(skip_serializing_if = "is_zero", default)]
    region_id: i64,
    #[serde(rename = "HostName")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    host_name: String,
    #[serde(rename = "CertName")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    cert_name: String,
    #[serde(rename = "IPv4")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    ipv4: String,
    #[serde(rename = "IPv6")]
    #[serde(skip_serializing_if = "String::is_empty", default)]
    ipv6: String,
    #[serde(rename = "STUNPort")]
    #[serde(skip_serializing_if = "is_zero", default)]
    stun_port: i64,
    #[serde(rename = "DERPPort")]
    #[serde(skip_serializing_if = "is_zero", default)]
    derp_port: i64,
    #[serde(rename = "InsecureForTests")]
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    insecure_for_tests: bool,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

mod hexserde {
    use serde::{Deserialize, Deserializer, Serializer};
    use crate::hex;

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

// We need a tiny hex implementation rather than adding another crate.
mod hex {
    pub fn encode(v: &[u8]) -> String {
        let mut s = String::with_capacity(v.len() * 2);
        for b in v {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn decode(s: String) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd hex length".into());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..s.len()).step_by(2) {
            let hi = hex_digit(bytes[i])?;
            let lo = hex_digit(bytes[i + 1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn hex_digit(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("invalid hex digit: {}", b as char)),
        }
    }
}

fn value_of_text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn value_of_int(n: i64) -> Value {
    Value::Integer(n.into())
}

fn int_from_value(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i64::try_from(*i).ok(),
        _ => None,
    }
}

fn text_from_value(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn bool_from_value(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn encode_conn_info(ci: &ConnInfo) -> Result<Vec<u8>, String> {
    if ci.server_public.len() != 32 {
        return Err(format!(
            "ServerPublic must be 32 bytes, got {}",
            ci.server_public.len()
        ));
    }

    let mut map: Vec<(Value, Value)> = Vec::with_capacity(3);
    map.push((value_of_text("p"), Value::Bytes(ci.server_public.clone())));

    if !ci.region.is_empty() {
        let regions: Vec<Value> = ci.region.iter().map(encode_region).collect();
        map.push((value_of_text("r"), Value::Array(regions)));
    }

    if ci.region_id != 0 {
        map.push((value_of_text("i"), value_of_int(ci.region_id)));
    }

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out)
        .map_err(|e| format!("CBOR encode: {}", e))?;
    Ok(out)
}

fn encode_region(r: &Region) -> Value {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(4);
    if r.region_id != 0 {
        map.push((value_of_text("i"), value_of_int(r.region_id)));
    }
    if !r.region_code.is_empty() {
        map.push((value_of_text("c"), value_of_text(&r.region_code)));
    }
    if !r.region_name.is_empty() {
        map.push((value_of_text("m"), value_of_text(&r.region_name)));
    }
    if !r.nodes.is_empty() {
        let nodes: Vec<Value> = r.nodes.iter().map(encode_node).collect();
        map.push((value_of_text("N"), Value::Array(nodes)));
    }
    Value::Map(map)
}

fn encode_node(n: &Node) -> Value {
    let mut map: Vec<(Value, Value)> = Vec::with_capacity(9);
    if !n.name.is_empty() {
        map.push((value_of_text("n"), value_of_text(&n.name)));
    }
    if n.region_id != 0 {
        map.push((value_of_text("i"), value_of_int(n.region_id)));
    }
    if !n.host_name.is_empty() {
        map.push((value_of_text("h"), value_of_text(&n.host_name)));
    }
    if !n.cert_name.is_empty() {
        map.push((value_of_text("t"), value_of_text(&n.cert_name)));
    }
    if !n.ipv4.is_empty() {
        map.push((value_of_text("4"), value_of_text(&n.ipv4)));
    }
    if !n.ipv6.is_empty() {
        map.push((value_of_text("6"), value_of_text(&n.ipv6)));
    }
    if n.stun_port != 0 {
        map.push((value_of_text("s"), value_of_int(n.stun_port)));
    }
    if n.derp_port != 0 {
        map.push((value_of_text("d"), value_of_int(n.derp_port)));
    }
    if n.insecure_for_tests {
        map.push((value_of_text("x"), Value::Bool(true)));
    }
    Value::Map(map)
}

fn decode_conn_info(cbor_in: &[u8]) -> Result<ConnInfo, String> {
    let value: Value = ciborium::de::from_reader(cbor_in)
        .map_err(|e| format!("CBOR decode: {}", e))?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err("CBOR root is not a map".into()),
    };

    let mut ci = ConnInfo::default();
    for (k, v) in map {
        let key = text_from_value(&k).unwrap_or_default();
        match key.as_str() {
            "p" => {
                if let Value::Bytes(b) = v {
                    if b.len() != 32 {
                        return Err(format!("ServerPublic length {} != 32", b.len()));
                    }
                    ci.server_public = b;
                } else {
                    return Err("ServerPublic is not bytes".into());
                }
            }
            "r" => {
                if let Value::Array(arr) = v {
                    ci.region = arr.iter().map(decode_region).collect::<Result<_, _>>()?;
                }
            }
            "i" => ci.region_id = int_from_value(&v).ok_or("bad RegionID")?,
            _ => {}
        }
    }
    Ok(ci)
}

fn decode_region(v: &Value) -> Result<Region, String> {
    let map = match v {
        Value::Map(m) => m,
        _ => return Err("region is not a map".into()),
    };
    let mut r = Region::default();
    for (k, val) in map {
        let key = text_from_value(k).unwrap_or_default();
        match key.as_str() {
            "i" => r.region_id = int_from_value(val).ok_or("bad RegionID")?,
            "c" => r.region_code = text_from_value(val).unwrap_or_default(),
            "m" => r.region_name = text_from_value(val).unwrap_or_default(),
            "N" => {
                if let Value::Array(arr) = val {
                    r.nodes = arr.iter().map(decode_node).collect::<Result<_, _>>()?;
                }
            }
            _ => {}
        }
    }
    Ok(r)
}

fn decode_node(v: &Value) -> Result<Node, String> {
    let map = match v {
        Value::Map(m) => m,
        _ => return Err("node is not a map".into()),
    };
    let mut n = Node::default();
    for (k, val) in map {
        let key = text_from_value(k).unwrap_or_default();
        match key.as_str() {
            "n" => n.name = text_from_value(val).unwrap_or_default(),
            "i" => n.region_id = int_from_value(val).ok_or("bad RegionID")?,
            "h" => n.host_name = text_from_value(val).unwrap_or_default(),
            "t" => n.cert_name = text_from_value(val).unwrap_or_default(),
            "4" => n.ipv4 = text_from_value(val).unwrap_or_default(),
            "6" => n.ipv6 = text_from_value(val).unwrap_or_default(),
            "s" => n.stun_port = int_from_value(val).ok_or("bad STUNPort")?,
            "d" => n.derp_port = int_from_value(val).ok_or("bad DERPPort")?,
            "x" => n.insecure_for_tests = bool_from_value(val).unwrap_or(false),
            _ => {}
        }
    }
    Ok(n)
}

/// Encode JSON to CBOR.
#[no_mangle]
pub extern "C" fn wirecbor_encode_json(
    json_in: *const c_char,
    out_bytes: *mut *mut c_uchar,
    out_len: *mut usize,
) -> c_int {
    if json_in.is_null() || out_bytes.is_null() || out_len.is_null() {
        return 1;
    }
    let cstr = unsafe { CStr::from_ptr(json_in) };
    let json_str = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };
    let ci: ConnInfo = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return 3,
    };
    let cbor = match encode_conn_info(&ci) {
        Ok(v) => v,
        Err(_) => return 4,
    };
    let mut boxed = cbor.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);
    unsafe {
        *out_bytes = ptr;
        *out_len = len;
    }
    0
}

/// Decode CBOR to JSON.
#[no_mangle]
pub extern "C" fn wirecbor_decode_json(
    cbor_in: *const c_uchar,
    cbor_len: usize,
    out_json: *mut *mut c_char,
) -> c_int {
    if cbor_in.is_null() || out_json.is_null() || cbor_len > MAX_CBOR_LEN {
        return 1;
    }
    let input = unsafe { slice::from_raw_parts(cbor_in, cbor_len) };
    let ci = match decode_conn_info(input) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let json_str = match serde_json::to_string(&ci) {
        Ok(s) => s,
        Err(_) => return 3,
    };
    let cstring = match CString::new(json_str) {
        Ok(c) => c,
        Err(_) => return 4,
    };
    let ptr = cstring.into_raw();
    unsafe {
        *out_json = ptr;
    }
    0
}

/// Free a buffer returned by wirecbor_encode_json.
#[no_mangle]
pub extern "C" fn wirecbor_buffer_free(ptr: *mut c_uchar, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len));
    }
}

/// Free a string returned by wirecbor_decode_json.
#[no_mangle]
pub extern "C" fn wirecbor_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal() {
        let ci = ConnInfo {
            server_public: vec![0xab; 32],
            region_id: 302,
            ..Default::default()
        };
        let cbor = encode_conn_info(&ci).unwrap();
        let got = decode_conn_info(&cbor).unwrap();
        assert_eq!(got.server_public, ci.server_public);
        assert_eq!(got.region_id, ci.region_id);
    }

    #[test]
    fn round_trip_full() {
        let ci = ConnInfo {
            server_public: (0..32).collect(),
            region: vec![Region {
                region_id: 10,
                region_code: "sea".into(),
                region_name: "Seattle".into(),
                nodes: vec![Node {
                    name: "10b".into(),
                    region_id: 10,
                    host_name: "derp10b.tailscale.com".into(),
                    cert_name: "cert.example.com".into(),
                    ipv4: "192.73.240.161".into(),
                    ipv6: "2607:f740:f::a01".into(),
                    stun_port: 3478,
                    derp_port: 8443,
                    insecure_for_tests: true,
                }],
            }],
            region_id: 0,
        };
        let cbor = encode_conn_info(&ci).unwrap();
        let got = decode_conn_info(&cbor).unwrap();
        assert_eq!(got.server_public, ci.server_public);
        assert_eq!(got.region.len(), 1);
        assert_eq!(got.region[0].nodes[0].host_name, "derp10b.tailscale.com");
    }

    #[test]
    fn rejects_bad_public_key_length() {
        let ci = ConnInfo {
            server_public: vec![0xab; 31],
            ..Default::default()
        };
        assert!(encode_conn_info(&ci).is_err());
    }
}
