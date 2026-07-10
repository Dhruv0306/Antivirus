package com.antivirus.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DomainValidatorTest {

    @Test
    void validateAndNormalize_ShouldAcceptValidDomain() {
        assertEquals("example.com", DomainValidator.validateAndNormalize("example.com"));
    }

    @Test
    void validateAndNormalize_ShouldLowercaseDomain() {
        assertEquals("example.com", DomainValidator.validateAndNormalize("EXAMPLE.COM"));
    }

    @Test
    void validateAndNormalize_ShouldTrimWhitespace() {
        assertEquals("example.com", DomainValidator.validateAndNormalize("  example.com  "));
    }

    @Test
    void validateAndNormalize_ShouldAcceptSubdomains() {
        assertEquals("mail.example.co.uk", DomainValidator.validateAndNormalize("mail.example.co.uk"));
    }

    @Test
    void validateAndNormalize_ShouldAcceptHyphenatedLabels() {
        assertEquals("my-site.com", DomainValidator.validateAndNormalize("my-site.com"));
    }

    @Test
    void validateAndNormalize_ShouldRejectNull() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize(null));
    }

    @Test
    void validateAndNormalize_ShouldRejectBlank() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize("   "));
    }

    @Test
    void validateAndNormalize_ShouldRejectSingleLabelWithoutTld() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize("localhost"));
    }

    @Test
    void validateAndNormalize_ShouldRejectSpacesInDomain() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize("exa mple.com"));
    }

    @Test
    void validateAndNormalize_ShouldRejectLabelStartingWithHyphen() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize("-example.com"));
    }

    @Test
    void validateAndNormalize_ShouldRejectLabelEndingWithHyphen() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize("example-.com"));
    }

    @Test
    void validateAndNormalize_ShouldRejectDomainExceeding253Characters() {
        String label = "a".repeat(63);
        String tooLong = (label + ".").repeat(4) + "com"; // well over 253 chars
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize(tooLong));
    }

    @Test
    void validateAndNormalize_ShouldRejectTldOfSingleCharacter() {
        assertThrows(IllegalArgumentException.class, () -> DomainValidator.validateAndNormalize("example.c"));
    }
}