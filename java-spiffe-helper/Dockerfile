FROM eclipse-temurin:17-jdk AS builder
COPY . /builder
WORKDIR /builder
RUN ./gradlew java-spiffe-helper:assemble -ParchiveClassifier=docker

FROM eclipse-temurin:17-jre AS runner
ARG JAVA_SPIFFE_HELPER_VERSION="0.8.4"
COPY --from=builder /builder/java-spiffe-helper/build/libs/java-spiffe-helper-${JAVA_SPIFFE_HELPER_VERSION}-docker.jar /app/java-spiffe-helper.jar
ENTRYPOINT ["java"]
CMD ["-jar", "/app/java-spiffe-helper.jar"]
