use crate::{
    building_blocks::mt::MT,
    gadgets::{AllocVar, ToBytesGadget, UInt64},
    ivls::transition_function::VerifiableTransitionFunctionConfig,
    ledger_system::transition_function::TransitionFunction,
    Borrow, SynthesisError, ToBytes, Vec,
};
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_relations::r1cs::Namespace;
use ark_std::{
    io::{Result as IoResult, Write},
    vec,
};

/// the commitment in the IVLS systems
pub struct Commitment<VC: VerifiableTransitionFunctionConfig> {
    /// root hash of the state tree
    pub state_rh: <VC::MTState as MT<
        VC::F,
        <VC::TF as TransitionFunction<VC::F>>::Addr,
        <VC::TF as TransitionFunction<VC::F>>::AddrVar,
    >>::Digest,
    /// root hash of the history tree
    pub history_rh: <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::Digest,
}

impl<VC: VerifiableTransitionFunctionConfig> ToBytes for Commitment<VC> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.state_rh.write(&mut writer)?;
        self.history_rh.write(&mut writer)?;
        Ok(())
    }
}

impl<VC: VerifiableTransitionFunctionConfig> Clone for Commitment<VC> {
    fn clone(&self) -> Self {
        Commitment {
            state_rh: self.state_rh.clone(),
            history_rh: self.history_rh.clone(),
        }
    }
}

impl<VC: VerifiableTransitionFunctionConfig> Default for Commitment<VC> {
    fn default() -> Self {
        Commitment {
            state_rh: <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::Digest::default(),
            history_rh: <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::Digest::default(),
        }
    }
}

/// the commitment gadget in the IVLS system
pub struct CommitmentVar<VC: VerifiableTransitionFunctionConfig> {
    /// root hash of the state tree
    pub state_rh_g: <VC::MTState as MT<
        VC::F,
        <VC::TF as TransitionFunction<VC::F>>::Addr,
        <VC::TF as TransitionFunction<VC::F>>::AddrVar,
    >>::DigestVar,
    /// root hash of the history tree
    pub history_rh_g: <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar,
}

impl<VC: VerifiableTransitionFunctionConfig> AllocVar<Commitment<VC>, VC::F> for CommitmentVar<VC> {
    fn new_variable<T: Borrow<Commitment<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableTransitionFunctionConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let t = f()?;
        let cm = t.borrow().clone();

        let ns = cs.into();
        let cs = ns.cs();

        let state_rh_g = <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::DigestVar::new_variable(
            ark_relations::ns!(cs, "commitment_gadget_state_rh"),
            || Ok(&cm.state_rh),
            mode,
        )?;

        let history_rh_g =
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar::new_variable(
                ark_relations::ns!(cs, "commitment_gadget_history_rh"),
                || Ok(&cm.history_rh),
                mode,
            )?;

        Ok(CommitmentVar {
            state_rh_g,
            history_rh_g,
        })
    }
}

impl<VC: VerifiableTransitionFunctionConfig> ToBytesGadget<VC::F> for CommitmentVar<VC> {
    fn to_bytes(&self) -> Result<Vec<UInt8<VC::F>>, SynthesisError> {
        let mut res: Vec<UInt8<VC::F>> = Vec::new();

        let state_rh_bytes = self.state_rh_g.to_bytes()?;
        let history_rh_bytes = self.history_rh_g.to_bytes()?;

        res.extend_from_slice(&state_rh_bytes);
        res.extend_from_slice(&history_rh_bytes);

        Ok(res)
    }
}

impl<VC: VerifiableTransitionFunctionConfig> Clone for CommitmentVar<VC> {
    fn clone(&self) -> Self {
        CommitmentVar {
            state_rh_g: self.state_rh_g.clone(),
            history_rh_g: self.history_rh_g.clone(),
        }
    }
}

/// the PCD message for IVLS
pub struct VerifiableTransitionFunctionMsg<VC: VerifiableTransitionFunctionConfig> {
    /// the step count
    pub t: u64,
    /// the commitment
    pub cm: Commitment<VC>,
}

impl<VC: VerifiableTransitionFunctionConfig> Default for VerifiableTransitionFunctionMsg<VC> {
    fn default() -> Self {
        let t = 0;
        let cm = Commitment::<VC>::default();
        VerifiableTransitionFunctionMsg { t, cm }
    }
}

impl<VC: VerifiableTransitionFunctionConfig> Clone for VerifiableTransitionFunctionMsg<VC> {
    fn clone(&self) -> Self {
        VerifiableTransitionFunctionMsg {
            t: self.t,
            cm: self.cm.clone(),
        }
    }
}

impl<VC: VerifiableTransitionFunctionConfig> ToBytes for VerifiableTransitionFunctionMsg<VC> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.t.write(&mut writer)?;
        self.cm.write(&mut writer)?;
        Ok(())
    }
}

/// the PCD message gadget for IVLS
pub struct VerifiableTransitionFunctionMsgVar<VC: VerifiableTransitionFunctionConfig> {
    /// the step count
    pub t_g: UInt64<VC::F>,
    /// the commitment
    pub cm_g: CommitmentVar<VC>,
}

impl<VC: VerifiableTransitionFunctionConfig> AllocVar<VerifiableTransitionFunctionMsg<VC>, VC::F>
    for VerifiableTransitionFunctionMsgVar<VC>
{
    fn new_variable<T: Borrow<VerifiableTransitionFunctionMsg<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableTransitionFunctionConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let t = f()?;
        let msg = t.borrow().clone();

        let t_g = UInt64::<VC::F>::new_variable(
            ark_relations::ns!(cs, "msg_gadget_t"),
            || Ok(&msg.t),
            mode,
        )?;
        let cm_g = CommitmentVar::<VC>::new_variable(
            ark_relations::ns!(cs, "msg_gadget_cm"),
            || Ok(&msg.cm),
            mode,
        )?;

        Ok(VerifiableTransitionFunctionMsgVar { t_g, cm_g })
    }
}

impl<VC: VerifiableTransitionFunctionConfig> ToBytesGadget<VC::F>
    for VerifiableTransitionFunctionMsgVar<VC>
{
    fn to_bytes(&self) -> Result<Vec<UInt8<VC::F>>, SynthesisError> {
        let mut res: Vec<UInt8<VC::F>> = Vec::new();
        let t_bytes = self.t_g.clone().to_bytes()?;
        let cm_bytes = self.cm_g.to_bytes()?;

        res.extend_from_slice(&t_bytes);
        res.extend_from_slice(&cm_bytes);

        Ok(res)
    }
}

/// Witness for IVLS's PCD
pub struct VerifiableTransitionFunctionWitness<VC: VerifiableTransitionFunctionConfig> {
    /// Transcript
    pub trans: <VC::TF as TransitionFunction<VC::F>>::Witness,
    /// Accessed addresses
    pub raddr: Vec<<VC::TF as TransitionFunction<VC::F>>::Addr>,
    /// Accessed data
    pub rdata: Vec<<VC::TF as TransitionFunction<VC::F>>::Data>,
    /// Merkle state tree lookup proofs
    pub read_proof: <VC::MTState as MT<
        VC::F,
        <VC::TF as TransitionFunction<VC::F>>::Addr,
        <VC::TF as TransitionFunction<VC::F>>::AddrVar,
    >>::LookupProof,
    /// Transaction
    pub tx: <VC::TF as TransitionFunction<VC::F>>::Tx,
    /// Written addresses
    pub waddr: Vec<<VC::TF as TransitionFunction<VC::F>>::Addr>,
    /// Written data
    pub wdata: Vec<<VC::TF as TransitionFunction<VC::F>>::Data>,
    /// Merkle state tree modifying proofs
    pub write_proof: <VC::MTState as MT<
        VC::F,
        <VC::TF as TransitionFunction<VC::F>>::Addr,
        <VC::TF as TransitionFunction<VC::F>>::AddrVar,
    >>::ModifyProof,
    /// Merkle history tree insertion proofs
    pub insert_proof: <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::ModifyProof,
}

impl<VC: VerifiableTransitionFunctionConfig> Default for VerifiableTransitionFunctionWitness<VC> {
    fn default() -> Self {
        let trans = <VC::TF as TransitionFunction<VC::F>>::Witness::default();
        let raddr = vec![
            <VC::TF as TransitionFunction<VC::F>>::Addr::default();
            <VC::TF as TransitionFunction<VC::F>>::NUM_READS
        ];
        let rdata = vec![
            <VC::TF as TransitionFunction<VC::F>>::Data::default();
            <VC::TF as TransitionFunction<VC::F>>::NUM_READS
        ];
        let read_proof =
            <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::default_lookup_proof(<VC::TF as TransitionFunction<VC::F>>::NUM_READS)
            .unwrap();
        let tx = <VC::TF as TransitionFunction<VC::F>>::Tx::default();
        let waddr = vec![
            <VC::TF as TransitionFunction<VC::F>>::Addr::default();
            <VC::TF as TransitionFunction<VC::F>>::NUM_WRITES
        ];
        let wdata = vec![
            <VC::TF as TransitionFunction<VC::F>>::Data::default();
            <VC::TF as TransitionFunction<VC::F>>::NUM_WRITES
        ];
        let write_proof =
            <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::default_modify_proof(<VC::TF as TransitionFunction<VC::F>>::NUM_WRITES)
            .unwrap();
        let insert_proof =
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::default_modify_proof(1).unwrap();

        VerifiableTransitionFunctionWitness {
            trans,
            raddr,
            rdata,
            read_proof,
            tx,
            waddr,
            wdata,
            write_proof,
            insert_proof,
        }
    }
}

impl<VC: VerifiableTransitionFunctionConfig> Clone for VerifiableTransitionFunctionWitness<VC> {
    fn clone(&self) -> Self {
        VerifiableTransitionFunctionWitness {
            trans: self.trans.clone(),
            raddr: self.raddr.clone(),
            rdata: self.rdata.clone(),
            read_proof: self.read_proof.clone(),
            tx: self.tx.clone(),
            waddr: self.waddr.clone(),
            wdata: self.wdata.clone(),
            write_proof: self.write_proof.clone(),
            insert_proof: self.insert_proof.clone(),
        }
    }
}

/// Witness gadget for IVLS's PCD
pub struct VerifiableTransitionFunctionWitnessVar<VC: VerifiableTransitionFunctionConfig> {
    /// Transcript
    pub trans_g: <VC::TF as TransitionFunction<VC::F>>::WitnessVar,
    /// Addresses of accessed data
    pub raddr_g: Vec<<VC::TF as TransitionFunction<VC::F>>::AddrVar>,
    /// Accessed data
    pub rdata_g: Vec<<VC::TF as TransitionFunction<VC::F>>::DataVar>,
    /// Merkle state tree lookup proofs
    pub read_proof_g: <VC::MTState as MT<
        VC::F,
        <VC::TF as TransitionFunction<VC::F>>::Addr,
        <VC::TF as TransitionFunction<VC::F>>::AddrVar,
    >>::LookupProofVar,
    /// Transaction
    pub tx_g: <VC::TF as TransitionFunction<VC::F>>::TxVar,
    /// Addresses of written data
    pub waddr_g: Vec<<VC::TF as TransitionFunction<VC::F>>::AddrVar>,
    /// Written data
    pub wdata_g: Vec<<VC::TF as TransitionFunction<VC::F>>::DataVar>,
    /// Merkle state tree modifying proofs
    pub write_proof_g: <VC::MTState as MT<
        VC::F,
        <VC::TF as TransitionFunction<VC::F>>::Addr,
        <VC::TF as TransitionFunction<VC::F>>::AddrVar,
    >>::ModifyProofVar,
    /// Merkle history tree insert proofs
    pub insert_proof_g: <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::ModifyProofVar,
}

impl<VC: VerifiableTransitionFunctionConfig>
    AllocVar<VerifiableTransitionFunctionWitness<VC>, VC::F>
    for VerifiableTransitionFunctionWitnessVar<VC>
{
    fn new_variable<T: Borrow<VerifiableTransitionFunctionWitness<VC>>>(
        cs: impl Into<Namespace<<VC as VerifiableTransitionFunctionConfig>::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let t = f()?;
        let witness = t.borrow().clone();

        let ns = cs.into();
        let cs = ns.cs();

        assert_eq!(
            witness.raddr.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_READS
        );
        assert_eq!(
            witness.rdata.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_READS
        );

        assert_eq!(
            witness.waddr.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_WRITES
        );
        assert_eq!(
            witness.wdata.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_WRITES
        );

        let trans_g = <VC::TF as TransitionFunction<VC::F>>::WitnessVar::new_variable(
            ark_relations::ns!(cs, "witness_gadget_trans"),
            || Ok(&witness.trans),
            mode,
        )?;

        let raddr_g = Vec::<<VC::TF as TransitionFunction<VC::F>>::AddrVar>::new_variable(
            ark_relations::ns!(cs, "witness_gadget_raddr"),
            || Ok(witness.raddr.clone()),
            mode,
        )?;
        let rdata_g = Vec::<<VC::TF as TransitionFunction<VC::F>>::DataVar>::new_variable(
            ark_relations::ns!(cs, "witness_gadget_rdata"),
            || Ok(witness.rdata.clone()),
            mode,
        )?;
        let read_proof_g = <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::LookupProofVar::new_variable(
            ark_relations::ns!(cs, "witness_gadget_read_proof"),
            || Ok(&witness.read_proof),
            mode,
        )?;
        let tx_g = <VC::TF as TransitionFunction<VC::F>>::TxVar::new_variable(
            ark_relations::ns!(cs, "witness_gadget_tx"),
            || Ok(&witness.tx),
            mode,
        )?;
        let waddr_g = Vec::<<VC::TF as TransitionFunction<VC::F>>::AddrVar>::new_variable(
            ark_relations::ns!(cs, "witness_gadget_waddr"),
            || Ok(witness.waddr.clone()),
            mode,
        )?;
        let wdata_g = Vec::<<VC::TF as TransitionFunction<VC::F>>::DataVar>::new_variable(
            ark_relations::ns!(cs, "witness_gadget_wdata"),
            || Ok(witness.wdata.clone()),
            mode,
        )?;
        let write_proof_g = <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::ModifyProofVar::new_variable(
            ark_relations::ns!(cs, "witness_gadget_write_proof"),
            || Ok(&witness.write_proof),
            mode,
        )?;
        let insert_proof_g =
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::ModifyProofVar::new_variable(
                ark_relations::ns!(cs, "witness_gadget_insert_proof"),
                || Ok(&witness.insert_proof),
                mode,
            )?;

        Ok(VerifiableTransitionFunctionWitnessVar {
            trans_g,
            raddr_g,
            rdata_g,
            read_proof_g,
            tx_g,
            waddr_g,
            wdata_g,
            write_proof_g,
            insert_proof_g,
        })
    }
}
