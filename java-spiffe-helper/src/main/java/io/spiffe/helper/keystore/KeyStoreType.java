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

   public static KeyStoreType parse(Object type) {
      if (String.valueOf(type).equalsIgnoreCase(JKS.value)) {
         return JKS;
      } else if (String.valueOf(type).equalsIgnoreCase(PKCS12.value)) {
         return PKCS12;
      } else {
          throw new IllegalArgumentException(String.format("KeyStore type not supported: %s", type));
      }
   }
}
