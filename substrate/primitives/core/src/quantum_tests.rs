#[cfg(test)]
mod tests {
    use crate::crypto::{QuantumKeyType, LamportClock, DoubleRatchetState};
    
    #[test]
    fn quantum_types_work() {
        let mut clock = LamportClock::new(1);
        clock.tick();
        assert_eq!(clock.timestamp, 1);
        
        let mut ratchet = DoubleRatchetState::new();
        ratchet.ratchet();
        assert_eq!(ratchet.message_num, 1);
    }
}
