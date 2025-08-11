// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Simplified HTM implementation without floating point for runtime compatibility

use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Simple HTM pattern detector for quantum coherence
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct SimpleHTM {
	/// Pattern memory
	pub patterns: Vec<Vec<u8>>,
	/// Coherence threshold (0-100)
	pub threshold: u8,
}

impl SimpleHTM {
	/// Create new HTM
	pub fn new(threshold: u8) -> Self {
		Self {
			patterns: Vec::new(),
			threshold,
		}
	}
	
	/// Learn a pattern
	pub fn learn_pattern(&mut self, pattern: Vec<u8>) {
		if pattern.len() > 0 && !self.patterns.contains(&pattern) {
			self.patterns.push(pattern);
		}
	}
	
	/// Recognize pattern with similarity score
	pub fn recognize(&self, input: &[u8]) -> u8 {
		if self.patterns.is_empty() || input.is_empty() {
			return 0;
		}
		
		let mut best_score = 0u8;
		
		for pattern in &self.patterns {
			if pattern.len() != input.len() {
				continue;
			}
			
			let mut matches = 0u32;
			for (a, b) in pattern.iter().zip(input.iter()) {
				if a == b {
					matches += 1;
				}
			}
			
			let score = (matches * 100 / pattern.len() as u32) as u8;
			if score > best_score {
				best_score = score;
			}
		}
		
		best_score
	}
	
	/// Detect anomaly
	pub fn is_anomaly(&self, input: &[u8]) -> bool {
		self.recognize(input) < self.threshold
	}
}

/// Quantum HTM for blockchain pattern recognition
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct QuantumHTM {
	/// Pattern detector
	pub detector: SimpleHTM,
	/// Quantum coherence patterns
	pub coherence_patterns: Vec<Vec<u8>>,
}

impl QuantumHTM {
	/// Create new Quantum HTM
	pub fn new() -> Self {
		Self {
			detector: SimpleHTM::new(70), // 70% similarity threshold
			coherence_patterns: Vec::new(),
		}
	}
	
	/// Process quantum measurements (0-255 scaled values)
	pub fn process_quantum_data(&mut self, measurements: &[u8]) -> u8 {
		// Learn from high coherence patterns
		let coherence_score = self.detector.recognize(measurements);
		
		if coherence_score > 80 {
			self.detector.learn_pattern(measurements.to_vec());
			self.coherence_patterns.push(measurements.to_vec());
		}
		
		coherence_score
	}
	
	/// Detect quantum anomaly
	pub fn detect_anomaly(&self, pattern: &[u8]) -> bool {
		self.detector.is_anomaly(pattern)
	}
}

impl Default for QuantumHTM {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	
	#[test]
	fn test_pattern_learning() {
		let mut htm = SimpleHTM::new(70);
		let pattern = vec![100, 150, 200, 250];
		
		htm.learn_pattern(pattern.clone());
		assert_eq!(htm.patterns.len(), 1);
		
		let score = htm.recognize(&pattern);
		assert_eq!(score, 100); // Perfect match
	}
	
	#[test]
	fn test_quantum_htm() {
		let mut qhtm = QuantumHTM::new();
		
		// High coherence pattern
		let high_coherence = vec![200, 210, 205, 195];
		let score = qhtm.process_quantum_data(&high_coherence);
		assert!(score <= 100);
		
		// Should learn the pattern
		assert_eq!(qhtm.coherence_patterns.len(), 1);
		
		// Similar pattern should not be anomaly
		let similar = vec![198, 208, 203, 193];
		assert!(!qhtm.detect_anomaly(&similar));
	}
}