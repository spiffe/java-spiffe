package io.spiffe.helper.keystore;

/**
 * KeyStore types supported by the KeyStoreHelper.
 */
public enum KeyStoreType {

   JKS("jks"),

   PKCS12("pkcs12");

   private final String value;

   KeyStoreType(final String value) {
      this.value = value;
   }

   public String value() {
      return value;
   }

   public static KeyStoreType getDefaultType() {
      return PKCS12;
   }

   /**
    * Parses an object to a KeyStoreType
    *
    * @param type an object representing a keystore type
    * @return an instance of a KeyStoreType
    * @throws IllegalArgumentException if the keystore type is unknown
    */
   public static KeyStoreType parse(final Object type) {
      KeyStoreType keyStoreType = null;
      if (String.valueOf(type).equalsIgnoreCase(JKS.value)) {
         keyStoreType = JKS;
      } else if (String.valueOf(type).equalsIgnoreCase(PKCS12.value)) {
         keyStoreType = PKCS12;
      }

      if (keyStoreType == null) {
         throw new IllegalArgumentException(String.format("KeyStore type not supported: %s", type));
      }
      return keyStoreType;
   }
}
