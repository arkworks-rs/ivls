use crate::{
    gadgets::{AllocVar, Assignment, EmptyVar, EqGadget, FpVar, UInt64},
    ledger_system::{state::State, transition_function::TransitionFunction},
    Borrow, Error, PhantomData, PrimeField, SynthesisError, ToBytes, Vec,
};
use ark_r1cs_std::alloc::AllocationMode;
use ark_relations::r1cs::{ConstraintSystemRef, Namespace};
use ark_std::io::{Result as IoResult, Write};

/// a transaction in this example ledger system
#[derive(Copy, Clone)]
pub struct ExampleTx<F: PrimeField> {
    /// the key
    pub key: u64,
    /// the value
    pub val: F,
}

impl<F: PrimeField> ToBytes for ExampleTx<F> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.key.write(&mut writer)?;
        self.val.write(&mut writer)?;
        Ok(())
    }
}

impl<F: PrimeField> Default for ExampleTx<F> {
    fn default() -> Self {
        ExampleTx::<F> {
            key: 0,
            val: F::default(),
        }
    }
}

/// the gadget for the transaction in this example ledger system
pub struct ExampleTxVar<F: PrimeField> {
    /// the key
    pub key_g: UInt64<F>,
    /// the value
    pub val_g: FpVar<F>,
}

impl<F: PrimeField> AllocVar<ExampleTx<F>, F> for ExampleTxVar<F> {
    fn new_variable<T: Borrow<ExampleTx<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let kv = *t.borrow();

        let key_g = UInt64::new_variable(
            ark_relations::ns!(cs, "example_tx_gadget_allocation_key"),
            || Ok(&kv.key),
            mode,
        )?;
        let val_g = FpVar::<F>::new_variable(
            ark_relations::ns!(cs, "example_tx_gadget_allocation_val"),
            || Ok(&kv.val),
            mode,
        )?;

        Ok(ExampleTxVar::<F> { key_g, val_g })
    }
}

/// an example transition function that sums up values
pub struct ExampleTransitionFunction<F: PrimeField> {
    #[doc(hidden)]
    f_phantom: PhantomData<F>,
}

impl<F: PrimeField> TransitionFunction<F> for ExampleTransitionFunction<F> {
    type Addr = u64;
    type Data = F;
    type Tx = ExampleTx<F>;
    type Witness = ();
    type Output = ();

    type AddrVar = UInt64<F>;
    type DataVar = FpVar<F>;
    type TxVar = ExampleTxVar<F>;
    type WitnessVar = EmptyVar<F>;

    const NUM_READS: usize = 1;
    const NUM_WRITES: usize = 1;

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
    > {
        let old_val: F = *state.read(&tx.key)?;
        let new_val: F = old_val + tx.val;

        state.write(&tx.key, &new_val)?;

        let mut raddr: Vec<Self::Addr> = Vec::with_capacity(Self::NUM_READS);
        let mut rdata: Vec<Self::Data> = Vec::with_capacity(Self::NUM_READS);
        raddr.push(tx.key);
        rdata.push(old_val);

        let mut waddr: Vec<Self::Addr> = Vec::with_capacity(Self::NUM_WRITES);
        let mut wdata: Vec<Self::Data> = Vec::with_capacity(Self::NUM_WRITES);
        waddr.push(tx.key);
        wdata.push(new_val);

        Ok(((), raddr, rdata, waddr, wdata, ()))
    }

    fn generate_constraints(
        _cs: ConstraintSystemRef<F>,
        _witness_g: &Self::WitnessVar,
        tx_g: &Self::TxVar,
        raddr_g: &[Self::AddrVar],
        rdata_g: &[Self::DataVar],
        waddr_g: &[Self::AddrVar],
        wdata_g: &[Self::DataVar],
    ) -> Result<(), SynthesisError> {
        assert_eq!(raddr_g.len(), Self::NUM_READS);
        assert_eq!(rdata_g.len(), Self::NUM_READS);
        assert_eq!(waddr_g.len(), Self::NUM_WRITES);
        assert_eq!(wdata_g.len(), Self::NUM_WRITES);

        // 1. Check if the raddr and waddr are correct.
        let tx_key = &tx_g.key_g;
        let raddr_key = raddr_g.get(0).get()?;
        let waddr_key = waddr_g.get(0).get()?;

        tx_key.enforce_equal(&raddr_key)?;
        tx_key.enforce_equal(&waddr_key)?;

        // 2. check if the wdata = rdata + tx.val
        let tx_val = &tx_g.val_g;
        let rdata_val = rdata_g.get(0).get()?;
        let wdata_val = wdata_g.get(0).get()?;

        let sum = tx_val + rdata_val;

        sum.enforce_equal(&wdata_val)?;

        Ok(())
    }
}
