spire-server:
  ca_subject:
    common_name: $TRUSTSTORE_COMMON_NAME
  controllerManager:
    identities:
      clusterSPIFFEIDs:
        default:
          enabled: false
        java-spiffe-helper:
          spiffeIDTemplate: spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}
          namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: default
          podSelector:
            matchLabels:
              app: java-spiffe-helper
          dnsNameTemplates:
            - $KEYSTORE_COMMON_NAME
