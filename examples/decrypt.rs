fn main() {
    #[cfg(feature = "serialization")]
    {
        use base64::{
            Engine,
            alphabet::STANDARD,
            engine::{GeneralPurpose, GeneralPurposeConfig},
        };
        use cosmian_cover_crypt::{Covercrypt, EncryptedHeader, UserSecretKey};
        use cosmian_crypto_core::bytes_ser_de::Serializable;

        const USK: &str = "MxSbPPKEfBhlW8keWBZWdGpgNcMqwVFSPKFZtZci9AufVsHxgVS8TCieQ3nVe6iDLOM/aNzbSCKHN9+FCNcGDQUCAgkBAAEE3eFOxWxajt3ycCBE8UNyDJhoDdVwmvAaM/xDiLMBAgMJAQBnqBpL3X0DHXMHASdf1hfKCBQ0j77FV5D5oVgHt6vjAQIECQEA5/Tt6K6/eOurFhJ9ncK6ogspN2q0WVGqOV9Bn4qwCgECAQkBAA//8a3pZrn6/AWYmoEzZSE5EaMK0FT/jYX4hDGpbekFAgUJAQF/KqQN0ERs5J6IG6cnKJf+k5WVyxtq1VR6thKF2Z32dY5p7HNq86sxKmFYds/qMC4zlI6JSycBM41VY45RuV3IKI5zDGBocXYWBogoN4+yyj41ZzFSqz6SeE8n7AZEqBxwA8rcGGCJMKhMxr28kqBznC+dGY3VjHOq08Z2SIMya508lW+S9r5puSRXcHJ48wAVUF5/ocFXQoRoS6XBGgGxucHttwL+w4goR0mq8Rxe3ME7uhiaBYZ6SD0b17olALv2UmMJdFVfFgCA2K7CQch8gEGjib4hkgAKQhvhpzFilazWtGd3R4ux167rbANJtltrySWge06t4DJxB9ArjD4Z4p8nE5YQSCZA88cmk0Y86mKC53tDUzJA+C/nDG/4+wcTa4CFtM9fJLoXc538RGXIjIRMyHZZZs5BJntgISW0rJN4xmADvMbN/ESc15SuLCMrpExW2Gc7QAdaF3NFm8onV3Y6Bapx8CyYRHhRNbisNwKBIQuI4jeZIgb2AUqfLMheUlWq9VJ+AoPHp1ATlz3sXD/VNQTB5y8YoDErBrt3ME1dYcdOa3+hyU9A9huyygDnY8ZsZqmqeL7UVnvoXLy/nDEKPHw/fIp0doaQyReWx5B8mAvgcJ140y359I0vkQuiZyKrrBvhwHD3OGXypD+/Rs7yFWKQc5gHKDq8W059WJwj0oDR+0wucSxK5nRNQ0r2ULyFI3/bdZwLvD0v6IUjmnDhWjlnUx02ISbH5Roc/LeJa1IyEYQ9Apqs+sAnqSm2Mc8r9yxL8JctOB1tUKPtdMDPtIItSKbArHgpxm8gSTiu+lRmUBYjxLoskiwve4cfSSsk5XmeGIfj+YyMabKKxMDQia/CRcRgGoMY0WLHsZUUUSS6lLpt8JyaWUfMaAgESynZhnCPgLNQZsc48RjVY835N2vpcbQoPBPhrKFXi8HrY8F9sSAv6q23jB9Md0CjUKktxb6zBWaLwjy+RTbM46qCMxR6FzDjJXMo2DTprKTZNMrTHKO8JJvm0hFO7ERlQqgvmByRGX+kgRBa5sTJZSMV2m4gSIjQ2XwSZTP24Z5WQCkU+oPX9zQYhZ3be5XgI4IboasPhDs0lLBOUwe9ElIZxcYX67sLYrEK8QV8HCT+7M9CqADQ+nuw2X4pyUtwZ09RiXYCRg2RMD+bNQ3/wJg54rJ3TLWCXGA4xzwnaD9spqdXvLYQAUEILGLhGbmZ08nR2ksyhY82qh7L2LG4+IMaU3EZRZzJZ8AZurqr7DNaxmEzQS8zRUzJywlHsSsaA6+DR20IdA4GMMO0Y4BVwmaOdX0VZBoqZnGUywUQwsnvF7kkeDNESogO7Im0Ix5LCgSy1RyUKWDnuyfwRaQ+pxTslk996KRuAjy8yGMEwYoX9ah31AWhsgcIawQcQai1QFiNS4v/+S7TSSkPdbRvs8xZIHciM2gBQSCeWVQSq7V+OUBhAjJ+6UzF+2fkuIpEIcBUCb9MZ0Dbayqz9w8oZ0jWcpiFqMUVXCjdY8gbTMmhV6pLN0bPdU7/GW+0+J3Bm2rj60HnUnrrKlWZYwtMzfh53VFiEkGgn+T7NI6kA/Jxo/vxx2iJPBk5H3ye4bb5lVenxImZvC2O1lPo5wqd";

        const HEADER: &str = "Rpdr/sTpWGaEiFPsUd6iiUMSnCvqpNlfE6kFjMkCNnnGepyEhr6JG6m4ipT9cU+wPHJXaTclpmRc4D7I5kfSKnisBd+BRMl4PlxpGNTXMDMBARPyduViPKAKcZ/gIA3exDx+/PLzArbYst1mVih5WE2mNPV5veD6EHKEwOnIkmqOMbKzbiWwj7+U5mRCGdjuPwU+lPuiZGqmlj3vrrwlOV5SNWISNZdOwcQQXSSdn1XnbFszTGSCi1oGWHX3OwTSzJPjldfcV0QimYJevUslYSvjy8svexQairc1JcidYSziAo4VALVEMXxG1VJJ1Zi/He4fncjl7zRBs8uPH9Hxz7ythXCxEbl+acnC5LUpA6uYGxGn9IWrjrJthc4OpNcANJUa5rcC+ByOH61UT2IvVhDN192sXZJP/GwH+rXefxAg/+uY1QJjwx8zMBvNpG6Glh+NW1B0sfMPpeP9YKlumIzVvRIw3673vkdjAxlMIGrCc6ul4n/VQlBqTy25Wuj82U1a7wcfSXfscGprZxr7gVRU5JdyG/HLJmrH6Nm0OD6yqtEfpXbKgdBz6lWyp/yn+TgfoMciKn7qI4E+BoJcbd20/uGOeOWSrcepUmVgCiuUqkCbgIqI7UXKQfMcQiXq+DxW4BQRGEvC1x7WpH3ikG8vDShNf7itHQ38OmMeokTd5gDvIrsrplV3DzeZ0atqZX0CxzM+CuFK67+wpvx3wLy1uS/H6xitWWl78eQEq4wd1xsA3jVV//yTrOPGSH3y+/7iWK+SZNfCCgrS8ZapuEcTDOoUDXnRXhpc+C4NIvPyBfZWEJWmURNp8H/nwYguC4mYXBZBtUeor+FKm54kbakS6sy2MD3rRh5Ruhs0sSOohc1lD7wn/8A19yeV41kIcj6AT04aPl7ApY0aLD2/X6YTq2tGfpcevAyJpt4Qs8uIqmSn9hRhCQcrmzhxeU6aXavfPkid2EUXaGwPtzT3RqJExH3VLgxvo1ByvFHYLHOv6gWt/dQ33q8JfSf17p23hNEziaBEQF4sqnyv0i8ENql/QjHszzhYf/vusV5Zt9KVCjbnzocC7KOeuhcuaUAovPFdy0Y/oFowcFQkWjtR7S0lWTT2DVqPYVdau9DPyJX7xrG9RPanyjPw3xm68B88tCGlgG9PmlGAJfHpKslwo7PxKrTQSvogPHe+Vvtan+kzlquEsC2jftJoxIfQhDVW4GiyeBYdJx8kBK05kZAPogUJptpxqqobFKO0NBF8Rhul+bB2dfXWEPId4hhldqJa3JazmQSmVsV1uxCU5uq8mYqrqXbb//w1PqyoWQHVSO1OWRmSacQUiIoVZKZMrI6nFvQT+H06UR9gBfWNVP9/kGovuU3oqcnBAfm5130NpTuNdg2nyYZpy2SUhxRqupbtyWTyniWNwVLZNa+hMaHRokr6AK1gEAry+Srf7y+UZYSLsvQIqgTiD3L/0A0G1xhoi7JIhj+o0WIH6SacJEociapH6k/3MfwlEgnYJwmitZ+eVkOxrB3OsieKbhRX9qqpJiAmc8053NqYaoZqRwpjCLPBAA==";

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
