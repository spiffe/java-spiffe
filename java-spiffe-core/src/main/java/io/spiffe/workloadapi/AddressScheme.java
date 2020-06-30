package io.spiffe.workloadapi;

/**
 * Address Scheme names enum.
 */
public enum AddressScheme {
    UNIX_SCHEME("unix"),
    TCP_SCHEME("tcp");

    private final String name;

    private AddressScheme(final String scheme) {
        this.name = scheme;
    }

    /**
     * Parses and returns an AddressScheme instance.
     *
     * @param scheme a string representing an Address Scheme ('unix' or 'tcp')
     * @return the enum instance representing the scheme
     * @throws IllegalArgumentException if the scheme is not 'unix' or 'tcp'
     */
    public static AddressScheme parseScheme(String scheme) {
        if ("unix".equals(scheme)) {
            return UNIX_SCHEME;
        } else if ("tcp".equals(scheme)) {
            return TCP_SCHEME;
        } else {
            throw new IllegalArgumentException("Address Scheme not supported: ");
        }
    }
}
