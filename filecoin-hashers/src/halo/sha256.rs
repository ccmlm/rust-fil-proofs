use std::cmp::Ordering;
use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use merkletree::{
    hash::{Algorithm, Hashable},
    merkle::Element,
};
use pasta_curves::arithmetic::FieldExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{sha256 as groth, Domain, HashFunction, Hasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256Domain<F: FieldExt> {
    // Wrapping `groth::Sha256Domain` allows us to reuse its method implementations.
    pub inner: groth::Sha256Domain,
    _f: PhantomData<F>,
}

impl<F: FieldExt> From<groth::Sha256Domain> for Sha256Domain<F> {
    fn from(domain: groth::Sha256Domain) -> Self {
        Sha256Domain {
            inner: domain,
            _f: PhantomData,
        }
    }
}

#[allow(clippy::from_over_into)]
impl<F: FieldExt> Into<groth::Sha256Domain> for Sha256Domain<F> {
    fn into(self) -> groth::Sha256Domain {
        self.inner
    }
}

// Disallow converting between fields; also BLS12-381's scalar field `Fr` size exceeds that of the
// Pasta curves.
impl<F: FieldExt> From<Fr> for Sha256Domain<F> {
    fn from(_fr: Fr) -> Self {
        panic!("cannot convert BLS12-381 scalar to halo::Sha256Domain")
    }
}

// Disallow converting between fields.
#[allow(clippy::from_over_into)]
impl<F: FieldExt> Into<Fr> for Sha256Domain<F> {
    fn into(self) -> Fr {
        panic!("cannot convert halo::Sha256Domain into BLS12-381 scalar")
    }
}

// TODO (jake): decide if this is needed?
/*
impl From<Fp> for Sha256Domain<Fp> {
    fn from(fp: Fp) -> Self {
        Sha256Domain {
            inner: groth::Sha256Domain(fp.to_repr()),
            _f: PhantomData,
        }
    }
}

impl From<Fq> for Sha256Domain<Fq> {
    fn from(fq: Fq) -> Self {
        Sha256Domain {
            inner: groth::Sha256Domain(fq.to_repr()),
            _f: PhantomData,
        }
    }
}
*/

impl<F: FieldExt> From<[u8; 32]> for Sha256Domain<F> {
    fn from(bytes: [u8; 32]) -> Self {
        Sha256Domain {
            inner: groth::Sha256Domain::from(bytes),
            _f: PhantomData,
        }
    }
}

impl<F: FieldExt> AsRef<[u8]> for Sha256Domain<F> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<F: FieldExt> AsRef<Self> for Sha256Domain<F> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<F: FieldExt> Default for Sha256Domain<F> {
    fn default() -> Self {
        Sha256Domain {
            inner: groth::Sha256Domain::default(),
            _f: PhantomData,
        }
    }
}

impl<F: FieldExt> PartialOrd for Sha256Domain<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl<F: FieldExt> Ord for Sha256Domain<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl<F: FieldExt> std::hash::Hash for Sha256Domain<F> {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        <groth::Sha256Domain as std::hash::Hash>::hash(&self.inner, hasher);
    }
}

impl<F: FieldExt> Element for Sha256Domain<F> {
    fn byte_len() -> usize {
        groth::Sha256Domain::byte_len()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        // Calling `.into()` is safe because `::from_slice()` does not check that the bytes are a
        // valid field element.
        groth::Sha256Domain::from_slice(bytes).into()
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        self.inner.copy_to_slice(bytes);
    }
}

impl<F: FieldExt> Domain for Sha256Domain<F> {
    type Field = F;

    fn into_bytes(&self) -> Vec<u8> {
        self.inner.into_bytes()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        groth::Sha256Domain::try_from_bytes(raw).map(Into::into)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        self.inner.write_bytes(dest)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // Generate a field element then convert to ensure that we stay within the field.
        let mut bytes = [0u8; 32];
        // Panics if `F::Repr` is not 32 bytes.
        bytes.copy_from_slice(F::random(rng).to_repr().as_ref());
        Sha256Domain {
            inner: groth::Sha256Domain(bytes),
            _f: PhantomData,
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Sha256Function<F: FieldExt> {
    inner: groth::Sha256Function,
    _f: PhantomData<F>,
}

impl<F: FieldExt> std::hash::Hasher for Sha256Function<F> {
    fn write(&mut self, msg: &[u8]) {
        self.inner.write(msg);
    }

    fn finish(&self) -> u64 {
        self.inner.finish()
    }
}

impl<F: FieldExt> Hashable<Sha256Function<F>> for Sha256Domain<F> {
    fn hash(&self, hasher: &mut Sha256Function<F>) {
        <groth::Sha256Domain as Hashable<groth::Sha256Function>>::hash(
            &self.inner,
            &mut hasher.inner,
        );
    }
}

impl<F: FieldExt> Algorithm<Sha256Domain<F>> for Sha256Function<F> {
    #[inline]
    fn hash(&mut self) -> Sha256Domain<F> {
        // Calling `.into()` is safe because the output of `.hash()` is guaranteed to be 254 bits.
        <groth::Sha256Function as Algorithm<groth::Sha256Domain>>::hash(&mut self.inner).into()
    }

    #[inline]
    fn reset(&mut self) {
        self.inner.reset();
    }

    fn leaf(&mut self, leaf: Sha256Domain<F>) -> Sha256Domain<F> {
        leaf
    }

    fn node(
        &mut self,
        left: Sha256Domain<F>,
        right: Sha256Domain<F>,
        _height: usize,
    ) -> Sha256Domain<F> {
        // Calling `.into()` is safe because the output of `.node()` is guaranteed to be 254 bits.
        self.inner.node(left.into(), right.into(), _height).into()
    }

    fn multi_node(&mut self, parts: &[Sha256Domain<F>], _height: usize) -> Sha256Domain<F> {
        let parts: Vec<groth::Sha256Domain> = parts.iter().map(|domain| (*domain).into()).collect();
        // Calling `.into()` is safe because the output of `.multi_node()` is guaranteed to be 254 bits.
        self.inner.multi_node(&parts, _height).into()
    }
}

impl<F: FieldExt> HashFunction<Sha256Domain<F>> for Sha256Function<F> {
    fn hash(data: &[u8]) -> Sha256Domain<F> {
        // Calling `.into()` is safe because the output of `.hash()` is guaranteed to be 254 bits.
        <groth::Sha256Function as HashFunction<groth::Sha256Domain>>::hash(data).into()
    }

    fn hash2(a: &Sha256Domain<F>, b: &Sha256Domain<F>) -> Sha256Domain<F> {
        // Calling `.into()` is safe because the output of `.hash2()` is guaranteed to be 254 bits.
        groth::Sha256Function::hash2(&a.inner, &b.inner).into()
    }

    fn hash_leaf_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _left: &AllocatedNum<Fr>,
        _right: &AllocatedNum<Fr>,
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::Sha256Function cannot be used within Groth16 circuits")
    }

    fn hash_multi_leaf_circuit<Arity, CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _leaves: &[AllocatedNum<Fr>],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::Sha256Function cannot be used within Groth16 circuits")
    }

    fn hash_md_circuit<CS: ConstraintSystem<Fr>>(
        _cs: &mut CS,
        _elements: &[AllocatedNum<Fr>],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::Sha256Function cannot be used within Groth16 circuits")
    }

    fn hash_leaf_bits_circuit<CS: ConstraintSystem<Fr>>(
        _cs: CS,
        _left: &[Boolean],
        _right: &[Boolean],
        _height: usize,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::Sha256Function cannot be used within Groth16 circuits")
    }

    fn hash_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _bits: &[Boolean],
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::Sha256Function cannot be used within Groth16 circuits")
    }

    fn hash2_circuit<CS: ConstraintSystem<Fr>>(
        mut _cs: CS,
        _a_num: &AllocatedNum<Fr>,
        _b_num: &AllocatedNum<Fr>,
    ) -> Result<AllocatedNum<Fr>, SynthesisError> {
        unimplemented!("halo::Sha256Function cannot be used within Groth16 circuits")
    }
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hasher<F: FieldExt> {
    _f: PhantomData<F>,
}

impl<F: FieldExt> Hasher for Sha256Hasher<F> {
    type Domain = Sha256Domain<F>;
    type Function = Sha256Function<F>;

    fn name() -> String {
        "sha256_halo_hasher".into()
    }
}
