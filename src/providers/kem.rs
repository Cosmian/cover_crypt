#[cfg(all(feature = "mlkem-512", feature = "mlkem-768"))]
compile_error!("only one MLKEM version can be chosen at a time");

pub mod mlkem;

#[cfg(feature = "mlkem-512")]
pub(crate) use mlkem::MlKem512 as MlKem;

#[cfg(feature = "mlkem-768")]
pub(crate) use mlkem::MlKem768 as MlKem;
