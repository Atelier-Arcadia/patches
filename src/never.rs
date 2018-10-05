/// A type with no values.
///
/// `Never` is used to communicate that a value of a particular type will
/// never be returned by a function.  This is a stable version of the
/// unstable [never type in the standard library](https://doc.rust-lang.org/beta/std/primitive.never.html).
///
/// # Examples
///
/// ```
/// // A function such as this can only return `None`.
/// fn dont_do_anything() -> Option<Never> {}
/// ```
///
/// ```
/// // A function such as this can only return `Ok(T)`.
/// fn always_succeed<T>() -> Result<T, Never> {}
/// ```
#[derive(Debug)]
pub enum Never {}
