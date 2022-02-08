use ff::PrimeField;
use filecoin_hashers::Domain;

pub fn encode<T: Domain>(key: T, value: T) -> T {
    let value = value.into_field();
    let mut result = key.into_field();

    encode_fr(&mut result, value);
    T::from_field(result)
}

pub fn encode_fr<F: PrimeField>(key: &mut F, value: F) {
    *key += value;
}

pub fn decode<T: Domain>(key: T, value: T) -> T {
    let mut result = value.into_field();
    let key = key.into_field();

    result -= key;
    T::from_field(result)
}
