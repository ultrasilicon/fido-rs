use crate::error::FidoError;

pub(crate) const fn check(code: i32) -> Result<(), FidoError> {
    match code {
        0 => Ok(()),
        _ => Err(FidoError::new(code)),
    }
}

macro_rules! str_or_none {
    ($ptr:ident) => {
        if $ptr.is_null() {
            None
        } else {
            let $ptr = unsafe {
                std::ffi::CStr::from_ptr($ptr)
                    .to_str()
                    .expect("invalid utf8")
            };

            Some($ptr)
        }
    };
}
