pub trait Keyed {
    type Key;
    fn from_key(key: Self::Key) -> Self;
}
