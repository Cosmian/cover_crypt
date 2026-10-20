#[cfg(not(any(feature = "mlkem-512", feature = "mlkem-768")))]
compile_error!("at leat one MLKEM version must be chosen");

pub mod mlkem;

#[cfg(all(feature = "mlkem-512", not(feature = "mlkem-768")))]
pub(crate) use mlkem::MlKem512 as MlKem;

#[cfg(feature = "mlkem-768")]
pub(crate) use mlkem::MlKem768 as MlKem;
