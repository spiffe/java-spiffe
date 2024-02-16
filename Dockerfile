FROM eclipse-temurin:17-jdk AS builder
WORKDIR /builder
COPY . /builder

RUN ./gradlew dependencies
RUN ./gradlew java-spiffe-helper:assemble -ParchiveClassifier=docker -Pversion=docker

FROM eclipse-temurin:17-jre AS runner
USER nobody

COPY conf/java-spiffe-helper.properties /app/java-spiffe-helper.properties
COPY --from=builder /builder/java-spiffe-helper/build/libs/java-spiffe-helper-docker-docker.jar /app/java-spiffe-helper.jar

ENTRYPOINT ["java", "-jar", "/app/java-spiffe-helper.jar"]
CMD ["--config", "/app/java-spiffe-helper.properties"]
