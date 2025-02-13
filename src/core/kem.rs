pub mod mlkem;

#[cfg(not(feature = "mlkem768"))]
pub use mlkem::MlKem512 as MlKem;

#[cfg(feature = "mlkem768")]
pub use mlkem::MlKem768 as MlKem;
