# Multi-stage build for Java application

# Stage 1: Build stage (optional if building in CI)
FROM maven:3.9.5-eclipse-temurin-21 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Runtime stage
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the built JAR from builder stage or from CI build artifacts
COPY --from=builder /app/target/*.jar app.jar

# Or if using CI build artifacts, comment above and uncomment below:
# COPY target/*.jar app.jar

# Create necessary directories with proper permissions
RUN mkdir -p /app/input /app/output && \
    chown -R appuser:appgroup /app

# Copy input files if needed
COPY input ./input

# Switch to non-root user
USER appuser

# Expose port if your application has a web interface
EXPOSE 8080

# Health check (adjust according to your application)
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD pgrep -f 'java.*app.jar' || exit 1

# Set JVM options
ENV JAVA_OPTS="-Xms512m -Xmx2048m -XX:+UseG1GC -XX:+UseContainerSupport"

# Run the application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
