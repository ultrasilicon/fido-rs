# fido-rs

libfido2 bindings for the Rust programming language.

# Example

1. Make a credential
```rust
use fido2_rs::device::Device;
use fido2_rs::credentials::CredentialRequest;
use fido2_rs::credentials::CoseType;
use anyhow::Result;

fn main() -> Result<()> {
    let dev = Device::open("windows://hello").expect("unable open windows hello");
 
    let request = CredentialRequest::builder()
        .client_data(&[1, 2, 3, 4, 5, 6])?
        .rp("fido_rs", "fido example")?
        .user(&[1, 2, 3, 4, 5, 6], "alice", Some("alice"), None)?
        .cose_type(CoseType::RS256)?
        .build();
    let cred = dev.make_credential(request, None)?;
    dbg!(cred.id());
    Ok(())
}
```

# Support platform
* Windows (MSVC and MinGW)
* Linux

# TODO

* [ ] more doc
* [ ] full bindings to `fido_cred_t` and `fido_assert_t`