// Benchmarks
// TL;DR; run
//   cargo run --release --features interfaces --bin bench_abe_gpsw -- --help
// for online help

use std::env;

use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
use cosmian_crypto_base::{
    hybrid_crypto::Metadata, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};
use cover_crypt::policies::ap;
use cover_crypt::{
    api::{CoverCrypt, PublicKey},
    error::Error,
    interfaces::statics::{decrypt_hybrid_header, encrypt_hybrid_header, EncryptedHeader},
    policies::{Attribute, Policy, PolicyAxis},
};
#[cfg(any(feature = "interfaces", feature = "ffi"))]
use std::time::Instant;
#[cfg(feature = "ffi")]
use {
    cover_crypt::interfaces::ffi::{
        error::get_last_error,
        hybrid_cc_aes::{
            h_aes_create_decryption_cache, h_aes_create_encryption_cache, h_aes_decrypt_header,
            h_aes_decrypt_header_using_cache, h_aes_destroy_decryption_cache,
            h_aes_destroy_encryption_cache, h_aes_encrypt_header, h_aes_encrypt_header_using_cache,
        },
    },
    std::{
        ffi::{CStr, CString},
        os::raw::c_int,
    },
};

#[allow(clippy::if_same_then_else)]
fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    let selector = if args.len() < 2 { "all" } else { &args[1] };
    if selector != "--help" {
        println!(
            "Bench selector: {}. Run with --help as parameter for details",
            selector
        );
    }
    if selector == "header_encryption_size" {
        bench_header_encryption_size()?;
    } else if selector == "header_encryption_speed" {
        bench_header_encryption_speed()?;
    } else if selector == "ffi_header_encryption" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption()?;
        }
    } else if selector == "ffi_header_enc_using_cache" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption_using_cache()?;
        }
    } else if selector == "header_decryption" {
        bench_header_decryption()?;
    } else if selector == "ffi_header_decryption" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_decryption()?;
        }
    } else if selector == "ffi_header_dec_using_cache" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_decryption_using_cache()?;
        }
    } else if selector == "all" {
        bench_header_encryption_size()?;
        bench_header_encryption_speed()?;
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption()?;
            bench_ffi_header_encryption_using_cache()?;
        }

        bench_header_decryption()?;
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_decryption()?;
            bench_ffi_header_decryption_using_cache()?;
        }
    } else {
        println!(
            r#"
Usage: cargo run --release --features ffi --bin bench_abe_gpsw -- [OPTION]
where [OPTION] is:

all                        : (or none) run all benches
header_encryption_size     : hybrid header encryption size
header_encryption_speed    : reference hybrid header encryption speed
ffi_header_encryption       : hybrid header encryption speed via FFI
ffi_header_enc_using_cache  : hybrid header encryption speed via FFI using a cache
header_decryption          : reference hybrid header decryption speed
ffi_header_decryption       : hybrid header decryption speed via FFI
ffi_header_dec_using_cache  : hybrid header decryption speed via FFI using a cache


To generate a flame graph:
--------------------------
1. Install cargo flamegraph: https://github.com/flamegraph-rs/flamegraph
2. On Linux, you will probably need to set these values in /etc/sysctl.conf and reboot
        kernel.perf_event_paranoid=-1
        kernel.kptr_restrict=0
3. Then generate the flamegraph SVG using

        CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --features ffi --bin bench_abe_gpsw -- OPTION

see above for the OPTION values
"#
        )
    }
    Ok(())
}

pub fn policy() -> Result<Policy, Error> {
    //
    // Policy settings
    //
    let sec_level = PolicyAxis::new(
        "Security Level",
        &["Protected", "Confidential", "Top Secret"],
        true,
    );
    let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
    let mut policy = Policy::new(100);
    policy.add_axis(&sec_level)?;
    policy.add_axis(&department)?;
    policy.rotate(&Attribute::new("Department", "FIN"))?;
    Ok(policy)
}

pub fn bench_header_encryption_size() -> Result<(), Error> {
    print!("Running header encryption size...");

    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, mpk) = cc.generate_master_keys(&policy)?;

    let policy_attributes_1 = vec![Attribute::new("Department", "FIN")];
    let encrypted_header_1 = encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &mpk,
        &policy_attributes_1,
        None,
    )?;

    let policy_attributes_2 = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let encrypted_header_2 = encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &mpk,
        &policy_attributes_2,
        None,
    )?;

    println!(
        "1 attribute: {} bytes, 2 attributes: {} bytes",
        encrypted_header_1.header_bytes.len(),
        encrypted_header_2.header_bytes.len()
    );

    Ok(())
}

pub fn bench_header_encryption_speed() -> Result<(), Error> {
    print!("Running 'direct' header encryption...");

    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, mpk) = cc.generate_master_keys(&policy)?;

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };
    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        let _encrypted_header = encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
            &policy,
            &mpk,
            &policy_attributes,
            Some(&meta_data),
        )?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

fn generate_encrypted_header(
    public_key: &PublicKey<X25519Crypto>,
) -> Result<EncryptedHeader<Aes256GcmCrypto>, Error> {
    // Policy

    let policy = policy()?;

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        public_key,
        &policy_attributes,
        Some(&meta_data),
    )
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_encryption() -> Result<(), Error> {
    print!("Running 'FFI' header encryption...");
    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, public_key) = cc.generate_master_keys(&policy)?;

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.to_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_encrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            header_bytes_ptr,
            &mut header_bytes_len,
            policy_ptr,
            public_key_ptr.cast::<i8>(),
            public_key_len,
            attributes_ptr,
            meta_data.uid.as_ptr().cast::<i8>(),
            meta_data.uid.len() as i32,
            meta_data
                .additional_data
                .as_ref()
                .unwrap()
                .as_ptr()
                .cast::<i8>(),
            meta_data.additional_data.as_ref().unwrap().len() as i32,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_encryption_using_cache() -> Result<(), Error> {
    print!("Running 'FFI' header encryption using cache...");
    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, public_key) = cc.generate_master_keys(&policy)?;

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.to_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr().cast::<i8>();
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;
    unwrap_ffi_error(h_aes_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        public_key_ptr,
        public_key_len,
    ))?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_encrypt_header_using_cache(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            header_bytes_ptr,
            &mut header_bytes_len,
            cache_handle,
            attributes_ptr,
            meta_data.uid.as_ptr().cast::<i8>(),
            meta_data.uid.len() as i32,
            meta_data
                .additional_data
                .as_ref()
                .unwrap()
                .as_ptr()
                .cast::<i8>(),
            meta_data.additional_data.as_ref().unwrap().len() as i32,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))?;
    Ok(())
}

///
/// # Safety

pub fn bench_header_decryption() -> Result<(), Error> {
    print!("Running direct header decryption...");

    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, public_key) = cc.generate_master_keys(&policy)?;
    let encrypted_header = generate_encrypted_header(&public_key)?;

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let user_decryption_key = cc.generate_user_private_key(&msk, &access_policy, &policy)?;

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        let _header_ = decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
            &user_decryption_key,
            &encrypted_header.header_bytes,
        )?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_decryption() -> Result<(), Error> {
    print!("Running FFI header decryption...");

    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, public_key) = cc.generate_master_keys(&policy)?;
    let encrypted_header = generate_encrypted_header(&public_key)?;

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let user_decryption_key = cc.generate_user_private_key(&msk, &access_policy, &policy)?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.to_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_decrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            uid_ptr,
            &mut uid_len,
            additional_data_ptr,
            &mut additional_data_len,
            encrypted_header.header_bytes.as_ptr().cast::<i8>(),
            encrypted_header.header_bytes.len() as c_int,
            user_decryption_key_ptr,
            user_decryption_key_len,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_decryption_using_cache() -> Result<(), Error> {
    print!("Running FFI header decryption using cache...");

    let policy = policy()?;

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, public_key) = cc.generate_master_keys(&policy)?;
    let encrypted_header = generate_encrypted_header(&public_key)?;

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let user_decryption_key = cc.generate_user_private_key(&msk, &access_policy, &policy)?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.to_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_decryption_cache(
        &mut cache_handle,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_decrypt_header_using_cache(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            uid_ptr,
            &mut uid_len,
            additional_data_ptr,
            &mut additional_data_len,
            encrypted_header.header_bytes.as_ptr().cast::<i8>(),
            encrypted_header.header_bytes.len() as c_int,
            cache_handle,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))?;

    Ok(())
}

#[cfg(feature = "ffi")]
unsafe fn unwrap_ffi_error(val: i32) -> Result<(), Error> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 4096];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr().cast::<i8>();
        let mut message_bytes_len = message_bytes_key.len() as c_int;
        get_last_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        return Err(Error::Other(format!("FFI ERROR: {}", cstr.to_str()?)));
    } else {
        Ok(())
    }
}
