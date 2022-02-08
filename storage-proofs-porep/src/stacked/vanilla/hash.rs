use std::marker::PhantomData;

use blstrs::Scalar as Fr;
use ff::PrimeField;
use filecoin_hashers::{
    halo::poseidon::{
        POSEIDON_CONSTANTS_11_PALLAS, POSEIDON_CONSTANTS_11_VESTA, POSEIDON_CONSTANTS_2_PALLAS,
        POSEIDON_CONSTANTS_2_VESTA,
    },
    POSEIDON_CONSTANTS_11, POSEIDON_CONSTANTS_2,
};
use generic_array::typenum::{U11, U2};
use lazy_static::lazy_static;
use neptune::poseidon::{Arity, Poseidon, PoseidonConstants};
use pasta_curves::{Fp, Fq};
use typemap::ShareMap;

lazy_static! {
    pub static ref POSEIDON_CONSTANTS: ShareMap = {
        let mut tm = ShareMap::custom();
        tm.insert::<FieldArity<Fr, U2>>(&*POSEIDON_CONSTANTS_2);
        tm.insert::<FieldArity<Fr, U11>>(&*POSEIDON_CONSTANTS_11);
        tm.insert::<FieldArity<Fp, U2>>(&*POSEIDON_CONSTANTS_2_PALLAS);
        tm.insert::<FieldArity<Fp, U11>>(&*POSEIDON_CONSTANTS_11_PALLAS);
        tm.insert::<FieldArity<Fq, U2>>(&*POSEIDON_CONSTANTS_2_VESTA);
        tm.insert::<FieldArity<Fq, U11>>(&*POSEIDON_CONSTANTS_11_VESTA);
        tm
    };
}

pub struct FieldArity<F, A>(PhantomData<(F, A)>)
where
    F: PrimeField,
    A: Arity<F>;

impl<F, A> typemap::Key for FieldArity<F, A>
where
    F: PrimeField,
    A: Arity<F>,
{
    type Value = &'static PoseidonConstants<F, A>;
}

/// Hash all elements in the given column.
pub fn hash_single_column<F: PrimeField>(column: &[F]) -> F {
    match column.len() {
        2 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U2>>()
                .expect("Poseidon constants not found for field and arity-2");
            Poseidon::new_with_preimage(column, consts).hash()
        }
        11 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U11>>()
                .expect("Poseidon constants not found for field and arity-11");
            Poseidon::new_with_preimage(column, consts).hash()
        }
        _ => panic!("unsupported column size: {}", column.len()),
    }
}
