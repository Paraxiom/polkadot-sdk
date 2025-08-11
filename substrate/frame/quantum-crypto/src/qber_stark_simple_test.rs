#[cfg(test)]
mod tests {
    use winterfell::math::fields::f128::BaseElement;
    
    #[test]
    fn test_base_element_arithmetic() {
        let a = BaseElement::from(10u32);
        let b = BaseElement::from(20u32);
        let c = a + b;
        assert_eq!(c, BaseElement::from(30u32));
        
        let d = a * b;
        assert_eq!(d, BaseElement::from(200u32));
    }
    
    #[test]
    fn test_winterfell_imports() {
        // Just verify winterfell is working
        use winterfell::{ProofOptions, FieldExtension};
        
        let _options = ProofOptions::new(
            32,
            8,
            0,
            FieldExtension::None,
            8,
            127,
        );
        
        assert!(true); // If we get here, winterfell is working
    }
}