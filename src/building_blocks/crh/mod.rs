use crate::{Error, SynthesisError};
use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::{alloc::AllocVar, bits::uint8::UInt8, R1CSVar, ToBytesGadget};
use ark_std::rand::{CryptoRng, Rng};

/// The Bowe-Hopwood variant of the Pedersen hash
pub mod bowe_hopwood;

/// The Poseidon hash
pub mod poseidon;

/// CRH specifically for Merkle trees (with a two-to-one compression method)
pub trait CRHforMerkleTree {
    /// CRH output
    type Output: Clone + Eq + core::fmt::Debug + Default + ToBytes;
    /// CRH parameters
    type Parameters: Clone;

    /// CRH setup
    fn setup<R: Rng + CryptoRng>(r: &mut R) -> Result<Self::Parameters, Error>;

    /// Hash bytes to the CRH output
    fn hash_bytes(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;

    /// Hash two CRH outputs into one output
    fn two_to_one_compress(
        parameters: &Self::Parameters,
        left: &Self::Output,
        right: &Self::Output,
    ) -> Result<Self::Output, Error>;

    /// Hash four CRH outputs into one output
    fn four_to_one_compress(
        parameters: &Self::Parameters,
        elts: &[Self::Output],
    ) -> Result<Self::Output, Error>;
}

/// CRH gadgets for Merkle trees
pub trait CRHforMerkleTreeGadget<CRH: CRHforMerkleTree, ConstraintF: PrimeField> {
    /// CRH output variable
    type OutputVar: Clone
        + AllocVar<CRH::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>;

    /// Hash UInt8 bytes to the CRH output variable
    fn hash_bytes(
        parameters: &CRH::Parameters,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;

    /// Hash two CRH output variables into one
    fn two_to_one_compress(
        parameters: &CRH::Parameters,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;

    /// Hash four CRH output variables into one
    fn four_to_one_compress(
        parameters: &CRH::Parameters,
        elts: &[Self::OutputVar],
    ) -> Result<Self::OutputVar, SynthesisError>;
}
