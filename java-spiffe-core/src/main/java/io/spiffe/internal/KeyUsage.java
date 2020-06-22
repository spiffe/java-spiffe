package io.spiffe.internal;

/**
 * Key Usages associated to their index in the X.509 key usage array.
 */
public enum KeyUsage {

    DIGITAL_SIGNATURE(0),
    NON_REPUDIATION(1),
    KEY_ENCIPHERMENT(2),
    DATA_ENCIPHERMENT(3),
    KEY_AGREEMENT(4),
    KEY_CERT_SIGN(5),
    CRL_SIGN(6),
    ENCIPHER_ONLY(7),
    DECIPHER_ONLY(8);
    
    private final int index;

    public int index() {
        return index;
    }

    KeyUsage(final int index) {
        this.index = index;
    }
}
