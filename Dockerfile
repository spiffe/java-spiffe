FROM gradle:jdk17 AS builder
COPY --chown=gradle:gradle . /builder
WORKDIR /builder
RUN gradle dependencies
RUN gradle java-spiffe-helper:assemble -ParchiveClassifier=docker -Pversion=docker

FROM eclipse-temurin:17-jre AS runner
COPY --from=builder \
  --chown=nobody:nobody \
  /builder/java-spiffe-helper/build/libs/java-spiffe-helper-docker-docker.jar /app/java-spiffe-helper.jar
USER nobody
ENTRYPOINT ["java"]
CMD ["-jar", "/app/java-spiffe-helper.jar"]
