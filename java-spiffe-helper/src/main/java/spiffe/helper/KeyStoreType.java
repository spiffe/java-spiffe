package spiffe.helper;

/**
 * KeyStore types supported by the KeyStoreHelper
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
}
