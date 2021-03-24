use crate::gadgets::AllocVar;
use crate::{
    building_blocks::mt::MT,
    gadgets::{Boolean, CondSelectGadget, EqGadget, UInt64},
    ivls::{
        data_structures::{
            Commitment, VerifiableTransitionFunctionMsg, VerifiableTransitionFunctionMsgVar,
            VerifiableTransitionFunctionWitness, VerifiableTransitionFunctionWitnessVar,
        },
        state::AuxState,
    },
    ledger_system::{state::State, transition_function::TransitionFunction},
    Error, PrimeField, RngCore, Sized, SynthesisError, Vec,
};
use ark_pcd::{PCDPredicate, PCD};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_std::rand::CryptoRng;
use ark_std::vec;

/// a collection of types for an IVLS
pub trait VerifiableTransitionFunctionConfig: Sized {
    /// the main field
    type F: PrimeField;
    /// the original transition function
    type TF: TransitionFunction<Self::F>;

    /// Merkle tree for state
    type MTState: MT<
        Self::F,
        <Self::TF as TransitionFunction<Self::F>>::Addr,
        <Self::TF as TransitionFunction<Self::F>>::AddrVar,
    >;
    /// Merkle tree for history
    type MTHistory: MT<Self::F, u64, UInt64<Self::F>>;

    /// The PCD engine
    type I: PCD<Self::F>;
}

/// vF
pub struct VerifiableTransitionFunction<VC: VerifiableTransitionFunctionConfig> {
    /// Merkle tree public parameters
    pub pp_mt: (
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::PublicParameters,
        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ),
    /// digests for empty state and history
    pub empty_digest: (
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::Digest,
        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::Digest,
    ),
    /// the PCD pk
    pub ipk: Option<<VC::I as PCD<VC::F>>::ProvingKey>,
    /// the PCD vk
    pub ivk: Option<<VC::I as PCD<VC::F>>::VerifyingKey>,
}

impl<VC: VerifiableTransitionFunctionConfig> Clone for VerifiableTransitionFunction<VC> {
    fn clone(&self) -> Self {
        VerifiableTransitionFunction::<VC> {
            pp_mt: self.pp_mt.clone(),
            empty_digest: self.empty_digest.clone(),
            ipk: self.ipk.clone(),
            ivk: self.ivk.clone(),
        }
    }
}

impl<VC: VerifiableTransitionFunctionConfig> VerifiableTransitionFunction<VC> {
    /// vF.run
    pub fn run<R: RngCore + CryptoRng>(
        &mut self,
        state: &mut State<VC::F, VC::TF>,
        aux_state: &mut AuxState<VC>,
        tx: &<VC::TF as TransitionFunction<VC::F>>::Tx,
        rng: &mut R,
    ) -> Result<<VC::TF as TransitionFunction<VC::F>>::Output, Error> {
        let (y, raddr, rdata, waddr, wdata, cs_witness) =
            <VC::TF as TransitionFunction<VC::F>>::run(state, &tx)?;

        let mut z_old: Option<VerifiableTransitionFunctionMsg<VC>> = None;
        let mut ivc_proof_old: Option<<VC::I as PCD<VC::F>>::Proof> = None;
        let read_proof: <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::LookupProof;
        let insert_proof: <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::ModifyProof;
        let rh_history_new;
        let t_new: u64;

        if aux_state.t == 0 {
            /* the base case */
            t_new = 1;

            aux_state.init(&self.pp_mt.0, &self.pp_mt.1)?;

            let tree_history = aux_state.tree_history.as_ref().unwrap();
            rh_history_new = <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::root(
                &self.pp_mt.1,
                &tree_history,
            )?;

            let tree_state = aux_state.tree_state.as_ref().unwrap();
            read_proof = <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::lookup(&self.pp_mt.0, &tree_state, &raddr)?;

            insert_proof =
                <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::default_modify_proof(1)?;
        } else {
            /* not the base case */
            let t_old = aux_state.t;
            let cm_old = aux_state.cm.as_ref().unwrap().clone();
            z_old = Some(VerifiableTransitionFunctionMsg::<VC> {
                t: t_old,
                cm: cm_old.clone(),
            });
            ivc_proof_old = Some(aux_state.proof.as_ref().unwrap().clone());

            t_new = t_old + 1;

            let tree_state = aux_state.tree_state.as_ref().unwrap();
            read_proof = <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::lookup(&self.pp_mt.0, &tree_state, &raddr)?;

            let mut history_addr_vec = Vec::with_capacity(1);
            history_addr_vec.push(t_old);

            let mut history_data_vec = Vec::with_capacity(1);
            history_data_vec.push(cm_old);

            let mut tree_history = aux_state.tree_history.as_mut().unwrap();
            let insert_result =
                <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::_modify_and_apply(
                    &self.pp_mt.1,
                    &mut tree_history,
                    &history_addr_vec,
                    &history_data_vec,
                )?;
            rh_history_new = insert_result.0;
            insert_proof = insert_result.1;
        }

        let mut tree_state = aux_state.tree_state.as_mut().unwrap();
        let (rh_state_new, write_proof) =
            <VC::MTState as MT<
                VC::F,
                <VC::TF as TransitionFunction<VC::F>>::Addr,
                <VC::TF as TransitionFunction<VC::F>>::AddrVar,
            >>::_modify_and_apply(&self.pp_mt.0, &mut tree_state, &waddr, &wdata)?;

        let cm_new = Commitment::<VC> {
            state_rh: rh_state_new,
            history_rh: rh_history_new,
        };

        let z_new = VerifiableTransitionFunctionMsg {
            t: t_new,
            cm: cm_new.clone(),
        };

        let w = VerifiableTransitionFunctionWitness {
            trans: cs_witness,
            raddr,
            rdata,
            read_proof,
            tx: tx.clone(),
            waddr,
            wdata,
            write_proof,
            insert_proof,
        };

        let ivc_proof_new = if z_old.is_some() {
            VC::I::prove::<Self, R>(
                &self.ipk.clone().unwrap(),
                &self,
                &z_new,
                &w,
                &[z_old.unwrap()],
                &[ivc_proof_old.unwrap()],
                rng,
            )?
        } else {
            VC::I::prove::<Self, R>(&self.ipk.clone().unwrap(), &self, &z_new, &w, &[], &[], rng)?
        };

        aux_state.t = t_new;
        aux_state.cm = Some(cm_new);
        aux_state.proof = Some(ivc_proof_new);

        Ok(y)
    }

    /// vF.verify
    pub fn verify(
        &self,
        t: &u64,
        cm: &Commitment<VC>,
        ivc_proof: &<VC::I as PCD<VC::F>>::Proof,
    ) -> Result<bool, Error> {
        let z = VerifiableTransitionFunctionMsg {
            t: *t,
            cm: cm.clone(),
        };

        VC::I::verify::<Self>(&self.ivk.clone().unwrap(), &z, &ivc_proof)
    }
}

impl<VC: VerifiableTransitionFunctionConfig> PCDPredicate<VC::F>
    for VerifiableTransitionFunction<VC>
{
    type Message = VerifiableTransitionFunctionMsg<VC>;
    type MessageVar = VerifiableTransitionFunctionMsgVar<VC>;
    type LocalWitness = VerifiableTransitionFunctionWitness<VC>;
    type LocalWitnessVar = VerifiableTransitionFunctionWitnessVar<VC>;

    const PRIOR_MSG_LEN: usize = 1;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<VC::F>,
        msg: &Self::MessageVar,
        witness: &Self::LocalWitnessVar,
        prior_msgs: &[Self::MessageVar],
        _base_bit: &Boolean<VC::F>,
    ) -> Result<(), SynthesisError> {
        // base checks
        assert_eq!(
            witness.raddr_g.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_READS
        );
        assert_eq!(
            witness.rdata_g.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_READS
        );

        assert_eq!(
            witness.waddr_g.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_WRITES
        );
        assert_eq!(
            witness.wdata_g.len(),
            <VC::TF as TransitionFunction<VC::F>>::NUM_WRITES
        );

        // 1. Check that trans is valid
        VC::TF::generate_constraints(
            ark_relations::ns!(cs, "checking_transcript").cs(),
            &witness.trans_g,
            &witness.tx_g,
            &witness.raddr_g,
            &witness.rdata_g,
            &witness.waddr_g,
            &witness.wdata_g,
        )?;

        // 2. Check if t_new = t_old + 1
        let t_old = &prior_msgs[0].t_g;
        let t_new = &msg.t_g;
        let t_new_supposed = UInt64::addmany(&[t_old.clone(), UInt64::constant(1u64)])?;
        t_new.enforce_equal(&t_new_supposed)?;

        // 3. Check if t_old = 0
        let t_old_is_zero: Boolean<VC::F>;
        {
            let res = t_old
                .to_bits_le()
                .iter()
                .fold(Boolean::constant(false), |acc, x| acc.or(&x).unwrap());
            t_old_is_zero = res;
        }

        // 4. The lookup proof uses
        //         the old msg's state_rh_g if t_old_is_zero = 1,
        //         the pp's empty_digest_state_g if t_old_is_zero = 0,
        let empty_state_g = <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::DigestVar::new_constant(
            ark_relations::ns!(cs, "empty_state_g"),
            self.empty_digest.0.clone(),
        )?;

        let state_rh_g_selected = <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::DigestVar::conditionally_select(
            &t_old_is_zero,
            &prior_msgs[0].cm_g.state_rh_g,
            &empty_state_g,
        )?;

        // 5. Check the lookup proof
        let pp_mt_state_g = self.pp_mt.0.clone();
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::verify_lookup_gadget(
            ark_relations::ns!(cs, "read_proof").cs(),
            &pp_mt_state_g,
            &state_rh_g_selected,
            &witness.raddr_g,
            &witness.rdata_g,
            &witness.read_proof_g,
        )?;

        // 6. Check the update proof
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::conditionally_verify_modify_gadget(
            ark_relations::ns!(cs, "write_proof").cs(),
            &pp_mt_state_g,
            &state_rh_g_selected,
            &msg.cm_g.state_rh_g,
            &witness.waddr_g,
            &witness.wdata_g,
            &witness.write_proof_g,
            &Boolean::constant(true),
        )?;

        // 4. The insert proof uses
        //         the old msg's history_rh_g if t_old_is_zero = 1,
        //         the pp's empty_digest_history_g if t_old_is_zero = 0,
        let empty_digest_g =
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar::new_constant(
                ark_relations::ns!(cs, "empty_digest_g"),
                self.empty_digest.1.clone(),
            )?;

        let history_rh_g_selected =
            <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::DigestVar::conditionally_select(
                &t_old_is_zero,
                &prior_msgs[0].cm_g.history_rh_g,
                &empty_digest_g,
            )?;

        // 6. Check the insert proof
        let addr_g_vec = vec![t_old.clone()];
        let data_g_vec = vec![prior_msgs[0].cm_g.clone()];

        let pp_mt_history_g = self.pp_mt.1.clone();

        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::conditionally_verify_modify_gadget(
            ark_relations::ns!(cs, "insert_proof").cs(),
            &pp_mt_history_g,
            &history_rh_g_selected,
            &msg.cm_g.history_rh_g,
            &addr_g_vec,
            &data_g_vec,
            &witness.insert_proof_g,
            &t_old_is_zero,
        )?;

        Ok(())
    }
}
