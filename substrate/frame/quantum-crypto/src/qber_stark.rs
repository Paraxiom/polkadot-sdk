//! STARK proof system for QBER measurements
//! 
//! This module implements zero-knowledge proofs that allow nodes to prove
//! they calculated QBER correctly without revealing the raw quantum measurements.

use sp_std::{vec, vec::Vec};
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements, StarkField},
    Air, AirContext, Assertion, AuxRandElements, EvaluationFrame,
    ProofOptions, TraceInfo, TransitionConstraintDegree, FieldExtension,
    StarkDomain, Trace, TraceTable, TracePolyTable, AcceptableOptions,
    Prover, DefaultConstraintEvaluator, DefaultTraceLde,
    crypto::DefaultRandomCoin,
    matrix::ColMatrix,
};
use crate::quantum_hasher::QuantumHasher;
use core::marker::PhantomData;

// STARK proof parameters
const TRACE_WIDTH: usize = 8;
const PUBLIC_INPUTS: usize = 4;

/// Public inputs for QBER proof
#[derive(Clone, Debug)]
pub struct QberPublicInputs {
    pub qber_value: u32,        // QBER * 10000
    pub measurement_count: u32,  // Number of measurements
    pub device_id_hash: [u8; 32],
    pub environmental_hash: [u8; 32],
}

impl ToElements<BaseElement> for QberPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        
        // Convert QBER and count to field elements
        elements.push(BaseElement::from(self.qber_value as u64));
        elements.push(BaseElement::from(self.measurement_count as u64));
        
        // Hash device ID and environmental data to field elements
        let device_elem = BaseElement::from(u64::from_le_bytes(self.device_id_hash[0..8].try_into().unwrap()));
        let env_elem = BaseElement::from(u64::from_le_bytes(self.environmental_hash[0..8].try_into().unwrap()));
        
        elements.push(device_elem);
        elements.push(env_elem);
        
        elements
    }
}

/// QBER AIR (Algebraic Intermediate Representation)
pub struct QberAir {
    context: AirContext<BaseElement>,
    qber_result: BaseElement,
    measurement_count: BaseElement,
    device_hash: BaseElement,
    env_hash: BaseElement,
}

impl Air for QberAir {
    type BaseField = BaseElement;
    type PublicInputs = QberPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Define constraint degrees for each transition constraint
        let degrees = vec![
            TransitionConstraintDegree::new(2), // Error count accumulation
            TransitionConstraintDegree::new(2), // Total count accumulation
            TransitionConstraintDegree::new(2), // Running QBER calculation
            TransitionConstraintDegree::new(1), // Measurement validity
            TransitionConstraintDegree::new(1), // Basis match validity
        ];
        
        let num_assertions = 6; // Start and end assertions for key columns
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        
        let pub_elements = pub_inputs.to_elements();
        
        Self {
            context,
            qber_result: pub_elements[0],
            measurement_count: pub_elements[1],
            device_hash: pub_elements[2],
            env_hash: pub_elements[3],
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        
        // Column layout:
        // 0: error_count
        // 1: total_count
        // 2: running_qber (qber * 10000)
        // 3: basis_match (0 or 1)
        // 4: is_error (0 or 1)
        // 5: device_hash_component
        // 6: env_hash_component
        // 7: step_counter
        
        // Constraint 0: Error count increases only when basis matches and there's an error
        let error_increment = current[3] * current[4]; // basis_match * is_error
        result[0] = next[0] - current[0] - error_increment;
        
        // Constraint 1: Total count increases only when basis matches
        result[1] = next[1] - current[1] - current[3];
        
        // Constraint 2: QBER calculation consistency
        // qber = (error_count * 10000) / total_count
        let expected_qber = if current[1] != E::ZERO {
            (current[0] * E::from(10000u32)) / current[1]
        } else {
            E::ZERO
        };
        result[2] = next[2] - expected_qber;
        
        // Constraint 3: basis_match is binary (0 or 1)
        result[3] = current[3] * (current[3] - E::ONE);
        
        // Constraint 4: is_error is binary (0 or 1)
        result[4] = current[4] * (current[4] - E::ONE);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            // Initial state assertions
            Assertion::single(0, 0, BaseElement::ZERO), // error_count starts at 0
            Assertion::single(1, 0, BaseElement::ZERO), // total_count starts at 0
            Assertion::single(2, 0, BaseElement::ZERO), // qber starts at 0
            
            // Final state assertions
            Assertion::single(1, last_step, self.measurement_count), // final total_count
            Assertion::single(2, last_step, self.qber_result),      // final QBER
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![]
    }
}

/// QBER execution trace
pub struct QberTrace {
    trace: TraceTable<BaseElement>,
}

impl QberTrace {
    pub fn new(measurements: &[(bool, bool)], public_inputs: &QberPublicInputs) -> Self {
        let trace_length = measurements.len().next_power_of_two();
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);
        
        // Initialize first row with zeros (initial state)
        trace.set(0, 0, BaseElement::ZERO); // error_count = 0
        trace.set(1, 0, BaseElement::ZERO); // total_count = 0
        trace.set(2, 0, BaseElement::ZERO); // qber = 0
        trace.set(3, 0, BaseElement::ZERO); // no measurement yet
        trace.set(4, 0, BaseElement::ZERO); // no error yet
        trace.set(5, 0, BaseElement::from(public_inputs.device_id_hash[0] as u64));
        trace.set(6, 0, BaseElement::from(public_inputs.environmental_hash[0] as u64));
        trace.set(7, 0, BaseElement::ZERO); // step = 0
        
        let mut error_count = 0u64;
        let mut total_count = 0u64;
        
        // Process measurements starting from row 1
        for (i, (basis_match, has_error)) in measurements.iter().enumerate() {
            let row = i + 1;
            if row >= trace_length {
                break;
            }
            
            // Update counts based on previous measurement
            if *basis_match {
                total_count += 1;
                if *has_error {
                    error_count += 1;
                }
            }
            
            // Calculate running QBER
            let qber = if total_count > 0 {
                (error_count * 10000) / total_count
            } else {
                0
            };
            
            // Fill trace columns
            trace.set(0, row, BaseElement::from(error_count));
            trace.set(1, row, BaseElement::from(total_count));
            trace.set(2, row, BaseElement::from(qber));
            trace.set(3, row, BaseElement::from(*basis_match as u64));
            trace.set(4, row, BaseElement::from(*has_error as u64));
            
            // Device and environmental hash components
            trace.set(5, row, BaseElement::from(public_inputs.device_id_hash[row % 32] as u64));
            trace.set(6, row, BaseElement::from(public_inputs.environmental_hash[row % 32] as u64));
            trace.set(7, row, BaseElement::from(row as u64));
        }
        
        // Fill remaining rows with final values
        let last_data_row = measurements.len().min(trace_length - 1);
        for i in (last_data_row + 1)..trace_length {
            for col in 0..TRACE_WIDTH {
                trace.set(col, i, trace.get(col, last_data_row));
            }
        }
        
        Self { trace }
    }
}

impl Trace for QberTrace {
    type BaseField = BaseElement;

    fn length(&self) -> usize {
        self.trace.length()
    }
    
    fn info(&self) -> &TraceInfo {
        self.trace.info()
    }
    
    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        self.trace.main_segment()
    }
    
    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        self.trace.read_main_frame(row_idx, frame);
    }
}

/// QBER STARK prover
pub struct QberProver {
    options: ProofOptions,
}

impl QberProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for QberProver {
    type BaseField = BaseElement;
    type Air = QberAir;
    type Trace = QberTrace;
    type HashFn = QuantumHasher;
    type RandomCoin = DefaultRandomCoin<QuantumHasher>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> <Self::Air as Air>::PublicInputs {
        // Extract public inputs from the trace
        let last_step = trace.length() - 1;
        
        // Read final values
        let mut final_row = vec![BaseElement::ZERO; TRACE_WIDTH];
        // Read final values from the main frame
        let mut frame = EvaluationFrame::new(trace.info().width());
        trace.read_main_frame(last_step, &mut frame);
        final_row.copy_from_slice(frame.current());
        
        QberPublicInputs {
            qber_value: final_row[2].as_int() as u32,
            measurement_count: final_row[1].as_int() as u32,
            device_id_hash: [0u8; 32], // Would be provided externally
            environmental_hash: [0u8; 32], // Would be provided externally
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// QBER STARK wrapper - provides simplified API
pub struct QberStark {
    _phantom: PhantomData<()>,
}

impl QberStark {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
    
    /// Generate STARK proof for QBER measurement
    pub fn prove(
        &self,
        measurements: Vec<(bool, bool)>, // (basis_match, error)
        public_inputs: QberPublicInputs,
    ) -> Result<QberProof, &'static str> {
        // Create execution trace
        let trace = QberTrace::new(&measurements, &public_inputs);
        
        // Setup proof options
        let options = ProofOptions::new(
            32,  // number of queries
            8,   // blowup factor
            0,   // grinding factor
            FieldExtension::Quadratic,
            8,   // FRI folding factor
            127, // max remainder length (must be 2^n - 1)
        );
        
        // Create prover and generate proof
        let prover = QberProver::new(options);
        let proof = prover.prove(trace)
            .map_err(|_| "Failed to generate STARK proof")?;
        
        Ok(QberProof { proof })
    }
    
    /// Verify STARK proof for QBER measurement
    pub fn verify(
        &self,
        public_inputs: QberPublicInputs,
        proof: QberProof,
    ) -> Result<(), &'static str> {
        let options = ProofOptions::new(
            32,  // number of queries
            8,   // blowup factor
            0,   // grinding factor
            FieldExtension::Quadratic,
            8,   // FRI folding factor
            127, // max remainder length (must be 2^n - 1)
        );
        let acceptable_options = AcceptableOptions::OptionSet(vec![options]);
        winterfell::verify::<QberAir, QuantumHasher, DefaultRandomCoin<QuantumHasher>>(
            proof.proof,
            public_inputs,
            &acceptable_options,
        ).map_err(|_| "STARK proof verification failed")
    }
}

/// QBER STARK proof wrapper
pub struct QberProof {
    proof: winterfell::Proof,
}

impl QberProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        winterfell::Proof::from_bytes(bytes)
            .map(|proof| Self { proof })
            .map_err(|_| "Failed to deserialize STARK proof")
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        self.proof.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_qber_stark_proof() {
        // Create test measurements (10% QBER)
        let measurements: Vec<(bool, bool)> = vec![
            (true, false),  // Basis match, no error
            (true, true),   // Basis match, error
            (false, false), // No basis match (ignored)
            (true, false),  // Basis match, no error
            (true, false),  // Basis match, no error
            (true, false),  // Basis match, no error
            (true, false),  // Basis match, no error
            (true, false),  // Basis match, no error
            (true, false),  // Basis match, no error
            (true, false),  // Basis match, no error
        ];
        
        let public_inputs = QberPublicInputs {
            qber_value: 1000, // 10% QBER
            measurement_count: 9, // 9 basis matches
            device_id_hash: [1u8; 32],
            environmental_hash: [2u8; 32],
        };
        
        let stark = QberStark::new();
        
        // Generate proof
        let proof = stark.prove(measurements, public_inputs.clone())
            .expect("Proof generation failed");
        
        // Verify proof
        stark.verify(public_inputs, proof)
            .expect("Proof verification failed");
    }
}