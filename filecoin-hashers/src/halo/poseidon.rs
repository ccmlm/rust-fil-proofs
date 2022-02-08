use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::panic::panic_any;

use anyhow::ensure;
use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use generic_array::typenum::{Unsigned, U11, U2, U4, U8};
use lazy_static::lazy_static;
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use neptune::{poseidon::PoseidonConstants, Arity, Poseidon};
use pasta_curves::{arithmetic::FieldExt, Fp, Fq};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typemap::ShareMap;

use crate::{Domain, HashFunction, Hasher, PoseidonArity, PoseidonMDArity};

lazy_static! {
    pub static ref POSEIDON_CONSTANTS: ShareMap = {
        let mut tm = ShareMap::custom();
        tm.insert::<FieldArity<Fp, U2>>(PoseidonConstants::new());
        tm.insert::<FieldArity<Fp, U4>>(PoseidonConstants::new());
        tm.insert::<FieldArity<Fp, U8>>(PoseidonConstants::new());
        tm.insert::<FieldArity<Fq, U2>>(PoseidonConstants::new());
        tm.insert::<FieldArity<Fq, U4>>(PoseidonConstants::new());
        tm.insert::<FieldArity<Fq, U8>>(PoseidonConstants::new());
        tm
    };

    // The first use of `POSEIDON_CONSTANTS` will trigger the generatation of the Poseidon constants
    // for all common arities and Pasta fields; it makes sense to seperate the uncommon arities
    // (e.g. `U32`) from the common arities to reduce the cost of generating constants.
    pub static ref POSEIDON_MD_CONSTANTS: ShareMap = {
        let mut tm = ShareMap::custom();
        tm.insert::<FieldArity<Fp, PoseidonMDArity>>(PoseidonConstants::new());
        tm.insert::<FieldArity<Fq, PoseidonMDArity>>(PoseidonConstants::new());
        tm
    };

    // Used during column hashing.
    pub static ref POSEIDON_CONSTANTS_2_PALLAS: PoseidonConstants<Fp, U2> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11_PALLAS: PoseidonConstants<Fp, U11> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_2_VESTA: PoseidonConstants<Fq, U2> =
        PoseidonConstants::new();
    pub static ref POSEIDON_CONSTANTS_11_VESTA: PoseidonConstants<Fq, U11> =
        PoseidonConstants::new();
}

pub struct FieldArity<F, A>(PhantomData<(F, A)>)
where
    F: FieldExt,
    A: Arity<F>;

impl<F, A> typemap::Key for FieldArity<F, A>
where
    F: FieldExt,
    A: Arity<F>,
{
    type Value = PoseidonConstants<F, A>;
}

#[derive(Copy, Clone)]
pub struct PoseidonDomain<F: FieldExt>(pub <F as PrimeField>::Repr);

// Implement `PartialEq` by hand because `PrimeField::Repr` does not.
impl<F: FieldExt> PartialEq for PoseidonDomain<F> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

// Implement `Eq` by hand because `PrimeField::Repr` does not.
impl<F: FieldExt> Eq for PoseidonDomain<F> {}

// Note: this does not compare the values of field elements; it only compares their little-endian
// (bigint) bytes element-wise, e.g `[1u8, 3, 5]` is less than `[2]`.
impl<F: FieldExt> Ord for PoseidonDomain<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

// Note: this does not compare the values of field elements; it only compares their little-endian
// (bigint) bytes element-wise, e.g `[1u8, 3, 5]` is less than `[2]`.
impl<F: FieldExt> PartialOrd for PoseidonDomain<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.as_ref().cmp(other.0.as_ref()))
    }
}

impl<F: FieldExt> Default for PoseidonDomain<F> {
    fn default() -> Self {
        PoseidonDomain(<F as PrimeField>::Repr::default())
    }
}

// Disallow converting between fields; also BLS12-381's scalar field `Fr` size exceeds that of the
// Pasta curves.
impl<F: FieldExt> From<Fr> for PoseidonDomain<F> {
    fn from(_fr: Fr) -> Self {
        panic!("cannot convert BLS12-381 scalar to halo::PoseidonDomain")
    }
}

// Disallow converting between fields.
#[allow(clippy::from_over_into)]
impl<F: FieldExt> Into<Fr> for PoseidonDomain<F> {
    fn into(self) -> Fr {
        panic!("cannot convert halo::PoseidonDomain into BLS12-381 scalar")
    }
}

// TODO (jake): decide if this is needed?
/*
impl From<Fp> for PoseidonDomain<Fp> {
    fn from(fp: Fp) -> Self {
        PoseidonDomain(fp.to_repr())
    }
}

impl From<Fq> for PoseidonDomain<Fq> {
    fn from(fq: Fq) -> Self {
        PoseidonDomain(fq.to_repr())
    }
}
*/

impl<F: FieldExt> From<[u8; 32]> for PoseidonDomain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        let mut repr = <F as PrimeField>::Repr::default();
        // Panics if `F::Repr` is not 32 bytes (which should always be the case).
        repr.as_mut().copy_from_slice(&bytes);
        PoseidonDomain(repr)
    }
}

impl<F: FieldExt> AsRef<Self> for PoseidonDomain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F: FieldExt> AsRef<[u8]> for PoseidonDomain<F> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// Implement `Debug` by hand because `PrimeField::Repr` does not.
impl<F: FieldExt> Debug for PoseidonDomain<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "halo::PoseidonDomain({:?})", self.0.as_ref())
    }
}

// Implement `Serialize` by hand because `PrimeField::Repr` does not.
impl<F: FieldExt> Serialize for PoseidonDomain<F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut le_bytes = [0u8; 32];
        // Panics if `F::Repr` is not 32 bytes (which should always be the case).
        le_bytes.copy_from_slice(self.0.as_ref());
        le_bytes.serialize(s)
    }
}

// Implement `Deserialize` by hand because `PrimeField::Repr` does not.
impl<'de, F: FieldExt> Deserialize<'de> for PoseidonDomain<F> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let le_bytes = <[u8; 32]>::deserialize(d)?;
        Ok(PoseidonDomain::from(le_bytes))
    }
}

impl<F: FieldExt> Element for PoseidonDomain<F> {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match Self::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.0.as_ref());
    }
}

impl<F: FieldExt> std::hash::Hash for PoseidonDomain<F> {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        std::hash::Hash::hash(self.0.as_ref(), hasher);
    }
}

impl<F: FieldExt> Domain for PoseidonDomain<F> {
    type Field = F;

    fn into_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == Self::byte_len(), "invalid amount of bytes");
        let mut repr = <F as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        Ok(PoseidonDomain(repr))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        ensure!(dest.len() == Self::byte_len(), "invalid amount of bytes");
        dest.copy_from_slice(self.0.as_ref());
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // Generate a field element then convert to ensure that we stay within the field.
        PoseidonDomain(F::random(rng).to_repr())
    }
}

#[inline]
fn scalar_from_slice<F: FieldExt>(bytes: &[u8]) -> F {
    let mut repr = <F as PrimeField>::Repr::default();
    // Panics if `bytes` is not 32 bytes.
    repr.as_mut().copy_from_slice(bytes);
    F::from_repr_vartime(repr).expect("from_repr failure")
}

fn shared_hash<F: FieldExt>(data: &[u8]) -> PoseidonDomain<F> {
    // FIXME: We shouldn't unwrap here, but doing otherwise will require an interface change.
    // We could truncate so `bytes_into_frs` cannot fail, then ensure `data` is always `fr_safe`.
    let preimage: Vec<F> = data.chunks(32).map(scalar_from_slice).collect();
    PoseidonDomain(shared_hash_frs(&preimage).to_repr())
}

fn shared_hash_frs<F: FieldExt>(preimage: &[F]) -> F {
    match preimage.len() {
        2 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U2>>()
                .expect("Poseidon constants not found for field and arity-2");
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        4 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U4>>()
                .expect("Poseidon constants not found for field and arity-4");
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        8 => {
            let consts = &POSEIDON_CONSTANTS
                .get::<FieldArity<F, U8>>()
                .expect("Poseidon constants not found for field and arity-8");
            Poseidon::new_with_preimage(preimage, consts).hash()
        }
        n => panic!("unsupported arity for Poseidon hasher: {}", n),
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct PoseidonFunction<F: FieldExt>(F);

impl<F: FieldExt> std::hash::Hasher for PoseidonFunction<F> {
    fn write(&mut self, preimage: &[u8]) {
        self.0 = F::from_repr_vartime(shared_hash::<F>(preimage).0).expect("from_repr failure");
    }

    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

// Can't blanket impl `Hashable for F where F: FieldExt` because both `Hashable` and `FieldExt` are
// externally defined traits (see: Rust's "Trait Coherence"), therefore we must implement `Hashable`
// for each Pasta field `Fp` and `Fq`.
impl Hashable<PoseidonFunction<Fp>> for Fp {
    fn hash(&self, hasher: &mut PoseidonFunction<Fp>) {
        use std::hash::Hasher;
        hasher.write(self.to_repr().as_ref());
    }
}
impl Hashable<PoseidonFunction<Fq>> for Fq {
    fn hash(&self, hasher: &mut PoseidonFunction<Fq>) {
        use std::hash::Hasher;
        hasher.write(self.to_repr().as_ref());
    }
}

impl<F: FieldExt> Hashable<PoseidonFunction<F>> for PoseidonDomain<F> {
    fn hash(&self, hasher: &mut PoseidonFunction<F>) {
        use std::hash::Hasher;
        hasher.write(self.0.as_ref());
    }
}

impl<F: FieldExt> Algorithm<PoseidonDomain<F>> for PoseidonFunction<F> {
    fn hash(&mut self) -> PoseidonDomain<F> {
        PoseidonDomain::from_slice(self.0.to_repr().as_ref())
    }

    fn reset(&mut self) {
        self.0 = F::zero();
    }

    fn leaf(&mut self, leaf: PoseidonDomain<F>) -> PoseidonDomain<F> {
        leaf
    }

    fn node(
        &mut self,
        left: PoseidonDomain<F>,
        right: PoseidonDomain<F>,
        _height: usize,
    ) -> PoseidonDomain<F> {
        let preimage = [
            F::from_repr_vartime(left.0).expect("from_repr failure"),
            F::from_repr_vartime(right.0).expect("from_repr failure"),
        ];
        PoseidonDomain(shared_hash_frs(&preimage).to_repr())
    }

    fn multi_node(&mut self, preimage: &[PoseidonDomain<F>], _height: usize) -> PoseidonDomain<F> {
        let preimage: Vec<F> = match preimage.len() {
            2 | 4 | 8 => preimage
                .iter()
                .enumerate()
                .map(|(i, domain)| match F::from_repr_vartime(domain.0) {
                    Some(f) => f,
                    None => panic!("from_repr failure at: {}", i),
                })
                .collect(),
            arity => panic!("unsupported Halo Poseidon hasher arity: {}", arity),
        };
        PoseidonDomain(shared_hash_frs(&preimage).to_repr())
    }
}

impl<F: FieldExt> HashFunction<PoseidonDomain<F>> for PoseidonFunction<F> {
    fn hash(preimage: &[u8]) -> PoseidonDomain<F> {
        shared_hash(preimage)
    }

    fn hash2(a: &PoseidonDomain<F>, b: &PoseidonDomain<F>) -> PoseidonDomain<F> {
        let preimage = [
            F::from_repr_vartime(a.0).expect("from_repr failure"),
            F::from_repr_vartime(b.0).expect("from_repr failure"),
        ];
        let consts = &POSEIDON_CONSTANTS
            .get::<FieldArity<F, U2>>()
            .expect("Poseidon constants not found for field and arity-2");
        let digest = Poseidon::new_with_preimage(&preimage, consts).hash();
        PoseidonDomain(digest.to_repr())
    }

    fn hash_md(input: &[PoseidonDomain<F>]) -> PoseidonDomain<F> {
        assert!(
            input.len() > 1,
            "hash_md preimage must contain more than one element"
        );

        let arity = PoseidonMDArity::to_usize();
        let consts = &POSEIDON_MD_CONSTANTS
            .get::<FieldArity<F, PoseidonMDArity>>()
            .expect("Poseidon constants not found for field and arity-MD");

        let mut p = Poseidon::new(consts);

        let fr_input: Vec<F> = input
            .iter()
            .map(|x| F::from_repr_vartime(x.0).expect("from_repr failure"))
            .collect();

        // Calling `.expect()` will panic iff we call `.input()` more that `arity`
        // number of times prior to reseting the hasher (i.e. if we exceed the arity of the
        // Poseidon constants) or if `preimge.len() == 1`; we prevent both scenarios.
        let digest = fr_input[1..]
            .chunks(arity - 1)
            .fold(fr_input[0], |acc, frs| {
                p.reset();
                p.input(acc).expect("input failure");
                for fr in frs {
                    p.input(*fr).expect("input failure");
                }
                p.hash()
            });

        PoseidonDomain(digest.to_repr())
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::PoseidonFunction cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity: 'static + PoseidonArity, CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::PoseidonFunction cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::PoseidonFunction cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::PoseidonFunction cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::PoseidonFunction cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _a: &AllocatedNum<Fr>,
        _b: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::PoseidonFunction cannot be used within Groth16 circuits")
    }
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHasher<F: FieldExt> {
    _f: PhantomData<F>,
}

impl<F: FieldExt> Hasher for PoseidonHasher<F> {
    type Domain = PoseidonDomain<F>;
    type Function = PoseidonFunction<F>;

    fn name() -> String {
        "poseidon_halo_hasher".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use generic_array::typenum::U0;
    use merkletree::{merkle::MerkleTree, store::DiskStore};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    pub const TEST_SEED: [u8; 16] = [
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ];

    type Tree<F, U, V, W> = MerkleTree<
        <PoseidonHasher<F> as Hasher>::Domain,
        <PoseidonHasher<F> as Hasher>::Function,
        DiskStore<<PoseidonHasher<F> as Hasher>::Domain>,
        U,
        V,
        W,
    >;

    fn test_halo_poseidon_trees<U, V, W>()
    where
        U: Unsigned,
        V: Unsigned,
        W: Unsigned,
    {
        let base_height = 3;
        let base_arity = U::to_usize();
        let n_leafs = base_arity.pow(base_height);

        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        // Test Pallas.
        let leafs: Vec<PoseidonDomain<Fp>> = (0..n_leafs)
            .map(|_| PoseidonDomain::random(&mut rng))
            .collect();
        Tree::<Fp, U, V, W>::new(leafs).expect("failed to create Pallas tree");

        // Test Vesta.
        let leafs: Vec<PoseidonDomain<Fq>> = (0..n_leafs)
            .map(|_| PoseidonDomain::random(&mut rng))
            .collect();
        Tree::<Fq, U, V, W>::new(leafs).expect("failed to create Vesta tree");
    }

    #[test]
    fn test_halo_poseidon_trees_2_0_0() {
        test_halo_poseidon_trees::<U2, U0, U0>();
    }

    #[test]
    fn test_halo_poseidon_trees_4_0_0() {
        test_halo_poseidon_trees::<U4, U0, U0>();
    }

    #[test]
    fn test_halo_poseidon_trees_8_0_0() {
        test_halo_poseidon_trees::<U8, U0, U0>();
    }

    #[test]
    fn test_halo_poseidon_trees_8_2_0() {
        test_halo_poseidon_trees::<U8, U2, U0>();
    }

    #[test]
    fn test_halo_poseidon_trees_8_8_0() {
        test_halo_poseidon_trees::<U8, U8, U0>();
    }

    #[test]
    fn test_halo_poseidon_trees_8_8_2() {
        test_halo_poseidon_trees::<U8, U8, U2>();
    }
}
