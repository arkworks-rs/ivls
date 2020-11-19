use crate::{
    building_blocks::mt::MT,
    gadgets::UInt64,
    ivls::{
        data_structures::Commitment, state::AuxState,
        transition_function::VerifiableTransitionFunctionConfig,
    },
    ledger_system::{state::State, transition_function::TransitionFunction},
    Error, Vec,
};

/// vH
pub struct VerifiableHistory<VC: VerifiableTransitionFunctionConfig> {
    /// Merkle tree public parameters
    pub pp_mt: (
        <VC::MTState as MT<
            VC::F,
            <VC::TF as TransitionFunction<VC::F>>::Addr,
            <VC::TF as TransitionFunction<VC::F>>::AddrVar,
        >>::PublicParameters,
        <VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::PublicParameters,
    ),
}

impl<VC: VerifiableTransitionFunctionConfig> VerifiableHistory<VC> {
    /// History.prove
    pub fn prove(
        &self,
        _state: &State<VC::F, VC::TF>,
        aux_state: &AuxState<VC>,
        t: u64,
    ) -> Result<Option<<VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof>, Error> {
        if t == 0 {
            Ok(None)
        } else {
            let mut t_vec: Vec<u64> = Vec::with_capacity(1);
            t_vec.push(t);

            let tree = aux_state.tree_history.as_ref().unwrap();

            let proof = VC::MTHistory::lookup(&self.pp_mt.1, tree, &t_vec)?;

            Ok(Some(proof))
        }
    }

    /// History.verify
    pub fn verify(
        &self,
        cm: &Commitment<VC>,
        t: u64,
        cm_t: &Option<Commitment<VC>>,
        proof: &Option<<VC::MTHistory as MT<VC::F, u64, UInt64<VC::F>>>::LookupProof>,
    ) -> Result<bool, Error> {
        if t == 0 {
            if cm_t.is_none() && proof.is_none() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            let mut t_vec: Vec<u64> = Vec::with_capacity(1);
            t_vec.push(t);

            let mut cm_vec: Vec<Commitment<VC>> = Vec::with_capacity(1);
            cm_vec.push(cm_t.clone().unwrap());

            let lookup_proof = proof.as_ref().unwrap();

            VC::MTHistory::verify_lookup(
                &self.pp_mt.1,
                &cm.history_rh,
                &t_vec,
                &cm_vec,
                lookup_proof,
            )
        }
    }
}
