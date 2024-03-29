fn main() {
    #[cfg(feature = "serialization")]
    {
        use base64::{
            alphabet::STANDARD,
            engine::{GeneralPurpose, GeneralPurposeConfig},
            Engine,
        };
        use cosmian_cover_crypt::{Covercrypt, EncryptedHeader, UserSecretKey};
        use cosmian_crypto_core::bytes_ser_de::Serializable;

        const USK: &str = "sUBriVEsM8HowAKOsIs9Y5p+Xa8JwJf84rlBHXzfkg+BJ6PzK79cT37Wsku5pMVKrfi/eIWhufC2pjYNMBOUAgMAH+waKc6AuwtAaYXXUAJA0K/uc5A22nXEShVXykjZ8QIBuNMsBrpSQaW0hAZ0AFvJTlwSM2BgI8m5k4wj3kQQ9NaP4cK6VvwyFlx7ZwwMZkJoCSgfiPvN4XqeWmiw/hehgjU2HkgYDQJf9QABaUoa74qM42SBnNubVVVnPvO5zrZ++NgoIHt4VPJfsMu157i6bakhOEWJy/CduXYGqedOGsNpj+gq0VsanjqeJ9gZ6sKjCknGoTxbEipIrPUO5jqJLzmJilS0ycAhR1mYlGU9yApPithxeIMaQFAAegOUTVFDFausKPbDZ1IYEWyftONyaaelMyJF4eCQIWILEihLuoscwGkVlYmRttcNVrLDW3yHN/cFQgiBSNVOi/RTLSpdsaMtattwDcaEiRUvCxe2gfaCYQV9zPIsdfAG2TIf2MPLcqUu0EBnIohX/TKyOTavt7HB76d/pCWT7sceu/YldifCYUoWABA8GbnF6DurlVwhfYUKhThnchbP3mgsEUsy+vQlWIwvrwxgpgqaabNSwJIUCXttY6kYNjJbL5pkahaAnxYLRMcvvKfGtzwlX7ewINAFrMSUBua8abWzgIa2NWlt2/ON7tKrVIaqRMYs8KFJSSsQ4bGEhZfBjWEYacAho8bFMuqamQgxaJhyj/J+tZrA24A5ckmPSPeGOIKealWkQmy8f0oAPVsOGaQFcBwLMPe4qRl49tpM6kRgpsyOkeQYOdpQ7Rue0xMKR+UhdPJkzYcGoVlAIGRmvSQzamw0kEYYV6yWr7AHiiqPZ/AuS7RcYUzPB0tSZ9BSdJKSX1jGf2aCbPPD8DxQ6VVPqWOekHshGGBOEzqBPhxtpfQB/lhl2KG/XOgUB6Kqs/zF14oLvlBL2XU2fCaj76ydrdOlo5JSSLKU2pkWASMLNGIM5TUqBsi/D4A9lLlqW5dDOik4ujNLbMAl4Yt4HxOe+pGKhFexfwJBgdCB6IBsatK/nWnIMuW9ZZFbUQG7oTOuFMKvurQ2OsyWa9VA06ldDFWIOQyzgydm2pp3XnXKaJElyYMSE1Ef4KRgEqgYA6J8yNIoI0o092y/HUxAoWWc5PesDmeqbbaLFEFdAqJ4gerNbtS1uAQWIsJzHAC2pGgxmLE7WkaD1IQ3fFgTHPOR97EdlbbM5YGa78mUpHqS0NpYQpbHluRUbyJ9uyIcvAxHewmIKIfDKnZ1z+YG/sIccCY+tFlGxBApSym1tgRBREcgkcYUAogq5nsKY5mvhXxICTCU4WtxZLxl17CC6du5pRSH+9hAMvI2C5R/6udvXkaYc0Ki35WsO5QAHlOVLBwbKLfM9xlhPkFf9qkqgKoMfqEJDcOn79QfOVFFqSfDI9Ep7Wl2YMK3r1apC2gw9xmwjBsMkEYLq2lNH4l0OqGpXDpAQCMwyTEOs5XHjWpsgxIvDId3HDu2DCBKYhUavtYHSgHNUeITVraWmhI9ygkBVMJKLfUGIVq/UwQvhzeVFePNhhN59HuWSjCyonWG6iFQeCCb9Dq0z2DNowiOnVdDWIM5g7BRTgSKBBlE/kArtfaDPyCXENUnwOZDpka63VMCNGak45IkSPT5SN7pdkPW9uIQBaAb04uYPbnALTij4xUzLwkAqXQvjNzwE8/0JzoWmWfdf9zdi1jdzpG1ZTqir0h74gc=";

        const HEADER: &str = "dkKN4Ga3BcJyspF5FntqHYwXI/yoUugzqcF0DPCluyUckuqbpXDRgSWdnyh5k0wCNAD6BgOR3WXjjrg6bF/mR/ICzF1XqtqK5Fn0uZ7FgYkBAbjlkpf7VV3M7BrwEB1FIJ2ZhekRLPayJvvTTdE6DY9ddr3IbuzEiMASs2P5nRabJe+p1xLJ9Yp1+8roV6GgWy37m7ysu24nxtKKPiyCIh29zxt4WjG+rJZOS0iJ2ETEjGPG5yyY7LYsOwsp6tQlb/XGmqd91TxjobKOnRceYRV29E1vj/uwzyT8OtRfWVITK1v1ku4knbWPhXFGVdiUpME+QqZIrjulMPI/AKoABa925Eq8h7UM64p91288I5Lq+S8+ysIaJv2nlydxb9BZBg/NeG5YGD+NIKm0EXoDekmbX91rLktO0cgFYEhNm+43BvLLXoyD7iU2bT7dQKNMUxMyoDvhB40aOkTWKJGCFnnrLf+oSxGDkCWTNaWYCJ3qygxjETGdigQzV6bzaGh2f/pjAzRHwKJHgywW4E2BCGrM4BJZvjhl44sZ14HWLofl3hNzLfrdJLFZz7Ua3PxHlidQ+ZsZSOW61G9Xt5vwHYZDtQOMVcX7tyNTNmMoIlghHjm66H8JDtuiduy08VE+7/Bk2anWhljNX2f2a/+hOjMbzqG+zaAtgpppylkvG/WlR1xLohGlLKdAWYRETIrI0oKi8RKFNHdnuPCZRDHlHDjhc273rPvsn7FlolSSTxbjvyTacB7jNwKfxW32eEK82p04GQyVN5uEBQBZUG4heNnoba54ybeU66PbOOclgE+LoblnvE0lqv8VxbCvbM3VVxTJ0rMj8ZshcxEWDv1v8E1JkGeq3QcDK/Ww1wBDuwLhxY8xbKmD40bmS8nGkRTLDuyhtg009oboT4+SL83Dz5WXEBcwO2m8Noor0QgtMjuyCAR92gvNSvewk03Q6X80W5Rd+tvw6HMwnoevpKge56akgXnQPnx76h78jIrEZ8FDZ7g6dlqPf7Lr9PnWQKhVHZwh1CBN0Rbb0ylumpvkiSCV7kF1tqPE89LO31jmYdULuQmMclKRst+SdXWSM7t2J/CeFmTgSiJ896P95imsC3XcWvmJqk+qlBNynP/Azmn775H59UHj21t8z2sFYwYkDfDRyBSxVLW/08nz+9vVy05qmrUqej/Iv4sHHjE3cgLCD+rjPOHssoFdr4ubG441N+1HpvoxFbo0Yk/fNH9JzqQj09eA4Wx6t3fjOWYJ8CESyK7lKBANYrQ5IdYuY3tk/Z3uR/uYff2pKu6xuisLF66FVC80WokFlvCEoYLLJs/q2/16mMo7cqkbhI0SLJgaAK8wIvJUS64Xxb3+SVVPYkeVFywrAb89J0kg6txXIuOfHxGcDZu7QaEPQUos7pwnbZBeXb/Q1RHbEE6cXr1pGB6wU+0gABNzLLTRNHuu2qm33myLkNQRilOyR7EqrDmLwY3ysGE5tmxYH5+zEu7nR/rkozqwpueGmrDMibRRw14kLRCNh6YkqvKsbSg1Tg0EKZe2eLGG0mmgj5jcYqusRcVtAA==";

        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);

        let cc = Covercrypt::default();
        let usk = UserSecretKey::deserialize(&transcoder.decode(USK.as_bytes()).unwrap()).unwrap();
        let encrypted_header =
            EncryptedHeader::deserialize(&transcoder.decode(HEADER.as_bytes()).unwrap()).unwrap();
        for _ in 0..1000 {
            encrypted_header
                .decrypt(&cc, &usk, None)
                .expect("cannot decrypt hybrid header");
        }
    }
    #[cfg(not(feature = "serialization"))]
    println!("Use the `serialization` feature to run this example")
}
