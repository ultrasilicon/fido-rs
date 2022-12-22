use crate::credentials::{Extensions, Opt};
use crate::error::Result;
use crate::utils::check;
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr::NonNull;

/// FIDO assertions, contains one or more assertion.
pub struct Assertions {
    pub(crate) ptr: NonNull<ffi::fido_assert_t>,
}

/// A single FIDO assertion.
pub struct Assertion<'a> {
    ptr: NonNull<ffi::fido_assert_t>,
    idx: usize,
    _p: PhantomData<&'a ()>,
}

/// Request to get a assertion.
pub struct AssertRequest(pub(crate) Assertions);

/// Builder for [AssertRequest]
pub struct AssertRequestBuilder(Assertions);

impl AssertRequest {
    /// Return a [AssertRequestBuilder]
    pub fn builder() -> AssertRequestBuilder {
        AssertRequestBuilder::new()
    }
}

impl AssertRequestBuilder {
    /// Return a [AssertRequestBuilder]
    pub fn new() -> AssertRequestBuilder {
        unsafe {
            let assert = ffi::fido_assert_new();

            AssertRequestBuilder(Assertions {
                ptr: NonNull::new_unchecked(assert),
            })
        }
    }

    /// Set the client data hash of assert by specifying the assertion's unhashed client data.
    ///
    /// This is required by Windows Hello, which calculates the client data hash internally.
    ///
    /// For compatibility with Windows Hello, applications should use [AssertRequestBuilder::client_data]
    /// instead of [AssertRequestBuilder::client_data_hash].
    pub fn client_data(self, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        unsafe {
            check(ffi::fido_assert_set_clientdata(
                self.0.ptr.as_ptr(),
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(self)
    }

    /// See [AssertRequestBuilder::client_data]
    pub fn client_data_hash(self, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        unsafe {
            check(ffi::fido_assert_set_clientdata_hash(
                self.0.ptr.as_ptr(),
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(self)
    }

    /// Set the relying party id of assert.
    pub fn rp(self, id: impl AsRef<str>) -> Result<Self> {
        let id = CString::new(id.as_ref())?;

        unsafe {
            check(ffi::fido_assert_set_rp(self.0.ptr.as_ptr(), id.as_ptr()))?;
        }

        Ok(self)
    }

    /// Set the up (user presence) attribute of assert.
    ///
    /// **Default to [Opt::Omit]**
    pub fn up(self, up: Opt) -> Result<Self> {
        unsafe {
            check(ffi::fido_assert_set_up(self.0.ptr.as_ptr(), up as _))?;
        }

        Ok(self)
    }

    /// Set the uv (user verification) attribute of assert.
    ///
    /// **Default to [Opt::Omit]**
    pub fn uv(self, uv: Opt) -> Result<Self> {
        unsafe {
            check(ffi::fido_assert_set_uv(self.0.ptr.as_ptr(), uv as _))?;
        }

        Ok(self)
    }

    /// Set the extensions of assert to the bitmask flags.
    ///
    /// At the moment, only the FIDO_EXT_CRED_BLOB, FIDO_EXT_HMAC_SECRET, and FIDO_EXT_LARGEBLOB_KEY extensions are supported.
    pub fn extensions(self, flags: Extensions) -> Result<Self> {
        unsafe {
            check(ffi::fido_assert_set_extensions(
                self.0.ptr.as_ptr(),
                flags.bits(),
            ))?;
        }

        Ok(self)
    }

    /// Allow a credential in a FIDO2 assertion.
    ///
    /// Add id to the list of credentials allowed in assert.
    ///
    /// If fails, the existing list of allowed credentials is preserved.
    pub fn allow_credential(self, id: impl AsRef<[u8]>) -> Result<Self> {
        let id = id.as_ref();

        unsafe {
            check(ffi::fido_assert_allow_cred(
                self.0.ptr.as_ptr(),
                id.as_ptr(),
                id.len(),
            ))?;
        }

        Ok(self)
    }

    /// Build a request.
    pub fn build(self) -> AssertRequest {
        AssertRequest(self.0)
    }
}

impl Drop for Assertions {
    fn drop(&mut self) {
        let mut ptr = self.ptr.as_ptr();

        unsafe {
            ffi::fido_assert_free(&mut ptr);
        }

        let _ = std::mem::replace(&mut self.ptr, NonNull::dangling());
    }
}

impl Assertion<'_> {
    /// Return relying party ID of assert.
    pub fn rp_id(&self) -> Option<&str> {
        let rp_id = unsafe { ffi::fido_assert_rp_id(self.ptr.as_ptr()) };
        str_or_none!(rp_id)
    }

    /// Return user display name of assert.
    pub fn user_display_name(&self) -> Option<&str> {
        let display_name =
            unsafe { ffi::fido_assert_user_display_name(self.ptr.as_ptr(), self.idx) };

        str_or_none!(display_name)
    }

    /// Return user icon of assert.
    pub fn user_icon(&self) -> Option<&str> {
        let icon = unsafe { ffi::fido_assert_user_icon(self.ptr.as_ptr(), self.idx) };

        str_or_none!(icon)
    }

    /// Return user name of assert.
    pub fn user_name(&self) -> Option<&str> {
        let name = unsafe { ffi::fido_assert_user_name(self.ptr.as_ptr(), self.idx) };

        str_or_none!(name)
    }

    /// Return CBOR-encoded authenticator data
    pub fn authdata(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_authdata_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_authdata_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return client data hash.
    pub fn clientdata_hash(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_clientdata_hash_len(self.ptr.as_ptr()) };
        let ptr = unsafe { ffi::fido_assert_clientdata_hash_ptr(self.ptr.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return the credBlob attribute.
    pub fn blob(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_blob_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_blob_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return the hmac-secret attribute.
    ///
    /// The HMAC Secret Extension (hmac-secret) is a CTAP 2.0 extension.
    ///
    /// Note that the resulting hmac-secret varies according to whether user verification was performed by the authenticator.
    pub fn hmac_secret(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_hmac_secret_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_hmac_secret_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return largeBlobKey attribute.
    pub fn largeblob_key(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_largeblob_key_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_largeblob_key_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return user ID.
    pub fn user_id(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_user_id_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_user_id_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return signature
    pub fn signature(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_sig_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_sig_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return credential ID
    pub fn id(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_id_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_id_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return signature count.
    pub fn counter(&self) -> u32 {
        unsafe { ffi::fido_assert_sigcount(self.ptr.as_ptr(), self.idx) }
    }

    /// Return authenticator data flags.
    pub fn flags(&self) -> u8 {
        unsafe { ffi::fido_assert_flags(self.ptr.as_ptr(), self.idx) }
    }
}

impl Assertions {
    /// Return the number of assertion.
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_assert_count(self.ptr.as_ptr()) }
    }

    /// Return a iterator of contained assertion
    pub fn iter(&self) -> impl Iterator<Item = Assertion> {
        let count = self.count();

        AssertionIter {
            asserts: &self,
            idx: 0,
            count,
        }
    }
}

/// Iterator of assertion
pub struct AssertionIter<'a> {
    asserts: &'a Assertions,
    idx: usize,
    count: usize,
}

impl<'a> Iterator for AssertionIter<'a> {
    type Item = Assertion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.count {
            None
        } else {
            let item = Assertion {
                ptr: self.asserts.ptr,
                idx: self.idx,
                _p: PhantomData,
            };

            self.idx += 1;

            Some(item)
        }
    }
}
