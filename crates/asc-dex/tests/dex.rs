use asc_dex::Dex;

#[test]
fn huge_encoded_array_does_not_allocate() {
    let mut data = vec![0u8; 0x78];
    data[..8].copy_from_slice(b"dex\n035\0");
    data[0x70..0x75].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    let dex = Dex::parse(&data).unwrap();
    let err = dex.static_literals(0x70).unwrap_err();
    assert!(err.to_string().contains("count"), "{err}");
}

/// `[size=1, VALUE_ARRAY]` repeated, then a `VALUE_NULL` leaf.
fn nested_encoded_array(levels: usize) -> (Vec<u8>, u32) {
    let mut data = vec![0u8; 0x70];
    data[..8].copy_from_slice(b"dex\n035\0");
    let start = data.len() as u32;
    for _ in 0..levels {
        data.extend_from_slice(&[0x01, 0x1c]);
    }
    data.extend_from_slice(&[0x01, 0x1e]);
    (data, start)
}

#[test]
fn deep_encoded_values_stop_instead_of_overflowing_the_stack() {
    let (data, start) = nested_encoded_array(4096);
    let dex = Dex::parse(&data).unwrap();
    let err = dex.static_literals(start).unwrap_err();
    assert!(err.to_string().contains("nesting"), "{err}");
}

#[test]
fn a_shallow_encoded_array_still_decodes() {
    let (data, start) = nested_encoded_array(3);
    let dex = Dex::parse(&data).unwrap();
    let values = dex.static_literals(start).unwrap();
    assert_eq!(values, vec!["{{{null}}}".to_string()]);
}

fn one_encoded_value(header: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 0x70];
    data[..8].copy_from_slice(b"dex\n035\0");
    data.extend_from_slice(&[1, header]);
    data.extend_from_slice(payload);
    data
}

#[test]
fn oversized_float_encoding_returns_an_error() {
    for value_arg in 4..=7 {
        let data = one_encoded_value(0x10 | (value_arg << 5), &[0; 8]);
        let err = Dex::parse(&data)
            .unwrap()
            .static_literals(0x70)
            .unwrap_err();
        assert!(err.to_string().contains("value_arg"), "{err}");
    }
}

#[test]
fn encoded_value_arguments_must_fit_their_types() {
    let invalid_headers = [
        0x20, 0x42, 0x43, 0x84, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x3c, 0x3d, 0x3e, 0x5f,
    ];
    for header in invalid_headers {
        let data = one_encoded_value(header, &[0; 8]);
        let err = Dex::parse(&data)
            .unwrap()
            .static_literals(0x70)
            .unwrap_err();
        assert!(err.to_string().contains("value_arg"), "{header:#x}: {err}");
    }
}

#[test]
fn reserved_encoded_value_types_are_rejected() {
    for value_type in [0x01, 0x05, 0x07, 0x12, 0x14] {
        let data = one_encoded_value(value_type, &[0; 8]);
        let err = Dex::parse(&data)
            .unwrap()
            .static_literals(0x70)
            .unwrap_err();
        assert!(err.to_string().contains("encoded value type"), "{err}");
    }
}

#[test]
fn valid_numeric_encodings_preserve_values_at_width_boundaries() {
    let cases: &[(u8, &[u8], &str)] = &[
        (0x10, &[0x3f], "0.5"),
        (0x70, &1.5f32.to_le_bytes(), "1.5"),
        (0xf1, &(-2.5f64).to_le_bytes(), "-2.5"),
        (0x22, &(-32768i16).to_le_bytes(), "-32768"),
        (0x64, &i32::MIN.to_le_bytes(), "-2147483648"),
        (0xe6, &i64::MIN.to_le_bytes(), "-9223372036854775808"),
        (0x1f, &[], "false"),
        (0x3f, &[], "true"),
    ];
    for &(header, payload, expected) in cases {
        let data = one_encoded_value(header, payload);
        assert_eq!(
            Dex::parse(&data).unwrap().static_literals(0x70).unwrap(),
            vec![expected],
            "{header:#x}"
        );
    }
}
