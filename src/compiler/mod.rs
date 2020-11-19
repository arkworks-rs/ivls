use crate::ivls::history::VerifiableHistory;
use crate::ivls::state::VerifiableState;
use crate::ivls::transition_function::{
    VerifiableTransitionFunction, VerifiableTransitionFunctionConfig,
};

/// compiler for circuit-specific setup IVLS
pub mod circuit_specific_setup_compiler;
/// compiler for universal setup IVLS
pub mod universal_setup_compiler;

/// incrementally verifiable ledger systems
pub struct IVLS<VC: VerifiableTransitionFunctionConfig> {
    /// verifiable transition function
    pub vf: VerifiableTransitionFunction<VC>,
    /// verifiable state
    pub vs: VerifiableState<VC>,
    /// verifiable history
    pub vh: VerifiableHistory<VC>,
}
