use crate::{
    gadgets::{AllocVar, ToBytesGadget},
    ledger_system::state::State,
    Error, PrimeField, Sized, SynthesisError, ToBytes, Vec,
};
use ark_relations::r1cs::ConstraintSystemRef;

/// a trait for the transition function, which would be implemented by the user
pub trait TransitionFunction<F: PrimeField>: Sized {
    /// type of the address
    type Addr: ToBytes + Default + Eq + Clone + Ord;
    /// type of the data
    type Data: ToBytes + Clone + Default;
    /// witness
    type Witness: Default + Clone;
    /// transaction
    type Tx: ToBytes + Clone + Default;

    /// gadgets for the address in a Merkle tree
    type AddrVar: AllocVar<Self::Addr, F>;
    /// gadgets for the data in a Merkle tree
    type DataVar: AllocVar<Self::Data, F> + ToBytesGadget<F>;
    /// gadgets for a transaction
    type TxVar: AllocVar<Self::Tx, F>;
    /// gadgets for a witness
    type WitnessVar: AllocVar<Self::Witness, F>;

    /// output of the transition function
    type Output;

    /// number of reads the function would perform
    const NUM_READS: usize;
    /// number of writes the function would perform
    const NUM_WRITES: usize;

    /// compute the transition result
    fn run(
        state: &mut State<F, Self>,
        tx: &Self::Tx,
    ) -> Result<
        (
            Self::Output,
            Vec<Self::Addr>,
            Vec<Self::Data>,
            Vec<Self::Addr>,
            Vec<Self::Data>,
            Self::Witness,
        ),
        Error,
    >;

    /// generate the constraints for the ledger system itself only
    fn generate_constraints(
        cs: ConstraintSystemRef<F>,
        witness: &Self::WitnessVar,
        tx: &Self::TxVar,
        raddr: &[Self::AddrVar],
        rdata: &[Self::DataVar],
        waddr: &[Self::AddrVar],
        wdata: &[Self::DataVar],
    ) -> Result<(), SynthesisError>;
}
