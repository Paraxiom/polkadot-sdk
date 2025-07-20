// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Tonnetz lattice implementation for harmonic transformations.
//!
//! The Tonnetz (German for "tone network") is a conceptual lattice diagram
//! representing tonal space, with pitch classes arranged to show harmonic
//! relationships. We use this mathematical framework to model quantum states
//! and their transformations.

use crate::types::{TonnetzPosition, TonnetzTransform};
use sp_std::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// The Tonnetz lattice structure
#[derive(Clone, Encode, Decode, TypeInfo, Debug)]
pub struct TonnetzLattice {
	/// Lattice dimensions
	pub width: u8,
	pub height: u8,
	pub depth: u8,
	/// Current active nodes
	pub active_nodes: Vec<TonnetzPosition>,
}

impl TonnetzLattice {
	/// Create a new Tonnetz lattice
	pub fn new(width: u8, height: u8, depth: u8) -> Self {
		Self {
			width,
			height,
			depth,
			active_nodes: Vec::new(),
		}
	}
	
	/// Calculate harmonic distance between two positions
	pub fn harmonic_distance(pos1: &TonnetzPosition, pos2: &TonnetzPosition) -> u32 {
		let dx = (pos1.x as i32 - pos2.x as i32).abs() as u32;
		let dy = (pos1.y as i32 - pos2.y as i32).abs() as u32;
		let dz = (pos1.z as i32 - pos2.z as i32).abs() as u32;
		
		// Weighted distance based on musical intervals
		dx + dy * 7 + dz * 4
	}
	
	/// Find the nearest harmonic neighbor
	pub fn nearest_neighbor(&self, position: &TonnetzPosition) -> Option<TonnetzPosition> {
		self.active_nodes
			.iter()
			.filter(|&pos| pos != position)
			.min_by_key(|&pos| Self::harmonic_distance(position, pos))
			.cloned()
	}
	
	/// Apply a transformation to a position
	pub fn transform(position: &TonnetzPosition, transform: TonnetzTransform) -> TonnetzPosition {
		match transform {
			TonnetzTransform::Parallel => Self::parallel_transform(position),
			TonnetzTransform::LeadingTone => Self::leading_tone_transform(position),
			TonnetzTransform::Relative => Self::relative_transform(position),
		}
	}
	
	/// Parallel transformation (P): maps major triads to minor triads
	fn parallel_transform(pos: &TonnetzPosition) -> TonnetzPosition {
		TonnetzPosition {
			x: pos.x,
			y: pos.y.wrapping_add(1),
			z: pos.z,
			pitch_class: (pos.pitch_class + 3) % 12, // Minor third
		}
	}
	
	/// Leading-tone transformation (L): voice-leading transformation
	fn leading_tone_transform(pos: &TonnetzPosition) -> TonnetzPosition {
		TonnetzPosition {
			x: pos.x.wrapping_add(1),
			y: pos.y,
			z: pos.z,
			pitch_class: (pos.pitch_class + 1) % 12, // Semitone
		}
	}
	
	/// Relative transformation (R): maps major to relative minor
	fn relative_transform(pos: &TonnetzPosition) -> TonnetzPosition {
		TonnetzPosition {
			x: pos.x,
			y: pos.y,
			z: pos.z.wrapping_add(1),
			pitch_class: (pos.pitch_class + 4) % 12, // Major third
		}
	}
	
	/// Calculate the harmonic coherence between positions
	pub fn calculate_coherence(positions: &[TonnetzPosition]) -> u8 {
		if positions.is_empty() {
			return 0;
		}
		
		// Calculate centroid
		let mut sum_x = 0i32;
		let mut sum_y = 0i32;
		let mut sum_z = 0i32;
		
		for pos in positions {
			sum_x += pos.x as i32;
			sum_y += pos.y as i32;
			sum_z += pos.z as i32;
		}
		
		let count = positions.len() as i32;
		let centroid = TonnetzPosition {
			x: (sum_x / count) as i8,
			y: (sum_y / count) as i8,
			z: (sum_z / count) as i8,
			pitch_class: 0, // Not used for centroid
		};
		
		// Calculate variance from centroid
		let mut total_distance = 0u32;
		for pos in positions {
			total_distance += Self::harmonic_distance(pos, &centroid);
		}
		
		// Convert to coherence score (inverse of variance)
		let avg_distance = total_distance / positions.len() as u32;
		if avg_distance == 0 {
			100
		} else {
			(100u32.saturating_sub(avg_distance.min(100))) as u8
		}
	}
	
	/// Check if positions form a harmonic triad
	pub fn is_harmonic_triad(pos1: &TonnetzPosition, pos2: &TonnetzPosition, pos3: &TonnetzPosition) -> bool {
		// Check if pitch classes form a major or minor triad
		let mut pitches = [pos1.pitch_class, pos2.pitch_class, pos3.pitch_class];
		pitches.sort();
		
		// Check for major triad intervals (0, 4, 7)
		let major_triad = pitches[1] - pitches[0] == 4 && pitches[2] - pitches[1] == 3;
		
		// Check for minor triad intervals (0, 3, 7)
		let minor_triad = pitches[1] - pitches[0] == 3 && pitches[2] - pitches[1] == 4;
		
		major_triad || minor_triad
	}
	
	/// Find all harmonic triads in the active nodes
	pub fn find_harmonic_triads(&self) -> Vec<(TonnetzPosition, TonnetzPosition, TonnetzPosition)> {
		let mut triads = Vec::new();
		let nodes = &self.active_nodes;
		
		if nodes.len() < 3 {
			return triads;
		}
		
		// Check all combinations of three nodes
		for i in 0..nodes.len() - 2 {
			for j in i + 1..nodes.len() - 1 {
				for k in j + 1..nodes.len() {
					if Self::is_harmonic_triad(&nodes[i], &nodes[j], &nodes[k]) {
						triads.push((nodes[i].clone(), nodes[j].clone(), nodes[k].clone()));
					}
				}
			}
		}
		
		triads
	}
	
	/// Calculate the resonance strength at a position
	pub fn resonance_strength(&self, position: &TonnetzPosition) -> u8 {
		// Count nearby active nodes (within harmonic distance 3)
		let nearby_count = self.active_nodes
			.iter()
			.filter(|&pos| Self::harmonic_distance(position, pos) <= 3)
			.count();
		
		// More nearby nodes = stronger resonance
		((nearby_count as u8) * 10).min(100)
	}
	
	/// Get valid neighbor positions for a given position
	pub fn get_neighbors(position: &TonnetzPosition) -> Vec<TonnetzPosition> {
		let mut neighbors = Vec::new();
		
		// Six neighbors in 3D Tonnetz
		let offsets = [
			(1, 0, 0), (-1, 0, 0),  // X-axis neighbors
			(0, 1, 0), (0, -1, 0),  // Y-axis neighbors
			(0, 0, 1), (0, 0, -1),  // Z-axis neighbors
		];
		
		for (dx, dy, dz) in offsets.iter() {
			let new_x = position.x.saturating_add(*dx);
			let new_y = position.y.saturating_add(*dy);
			let new_z = position.z.saturating_add(*dz);
			
			// Check bounds
			if new_x.abs() <= 6 && new_y.abs() <= 4 && new_z.abs() <= 2 {
				neighbors.push(TonnetzPosition {
					x: new_x,
					y: new_y,
					z: new_z,
					pitch_class: Self::calculate_pitch_class(new_x, new_y, new_z),
				});
			}
		}
		
		neighbors
	}
	
	/// Calculate pitch class from Tonnetz coordinates
	fn calculate_pitch_class(x: i8, y: i8, z: i8) -> u8 {
		// Based on Tonnetz structure:
		// x-axis: semitones
		// y-axis: perfect fifths (7 semitones)
		// z-axis: major thirds (4 semitones)
		let pitch = (x as i32 + y as i32 * 7 + z as i32 * 4).rem_euclid(12);
		pitch as u8
	}
	
	/// Find the path between two positions using A* algorithm
	pub fn find_path(
		&self,
		start: &TonnetzPosition,
		end: &TonnetzPosition,
	) -> Option<Vec<TonnetzTransform>> {
		// Simplified pathfinding - in production would use full A*
		let mut path = Vec::new();
		let mut current = start.clone();
		
		// Try each transform and see which gets us closer
		for _ in 0..10 { // Max 10 steps
			if current == *end {
				return Some(path);
			}
			
			let transforms = [
				TonnetzTransform::Parallel,
				TonnetzTransform::LeadingTone,
				TonnetzTransform::Relative,
			];
			
			let mut best_transform = None;
			let mut best_distance = Self::harmonic_distance(&current, end);
			
			for transform in transforms.iter() {
				let new_pos = Self::transform(&current, transform.clone());
				let new_distance = Self::harmonic_distance(&new_pos, end);
				
				if new_distance < best_distance {
					best_distance = new_distance;
					best_transform = Some(transform.clone());
				}
			}
			
			if let Some(transform) = best_transform {
				current = Self::transform(&current, transform.clone());
				path.push(transform);
			} else {
				// No improvement possible
				break;
			}
		}
		
		if current == *end {
			Some(path)
		} else {
			None
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	
	#[test]
	fn test_harmonic_distance() {
		let pos1 = TonnetzPosition { x: 0, y: 0, z: 0, pitch_class: 0 };
		let pos2 = TonnetzPosition { x: 1, y: 1, z: 1, pitch_class: 0 };
		
		assert_eq!(TonnetzLattice::harmonic_distance(&pos1, &pos2), 12);
	}
	
	#[test]
	fn test_transformations() {
		let pos = TonnetzPosition { x: 0, y: 0, z: 0, pitch_class: 0 };
		
		let p_transform = TonnetzLattice::transform(&pos, TonnetzTransform::Parallel);
		assert_eq!(p_transform.pitch_class, 3);
		
		let l_transform = TonnetzLattice::transform(&pos, TonnetzTransform::LeadingTone);
		assert_eq!(l_transform.pitch_class, 1);
		
		let r_transform = TonnetzLattice::transform(&pos, TonnetzTransform::Relative);
		assert_eq!(r_transform.pitch_class, 4);
	}
}