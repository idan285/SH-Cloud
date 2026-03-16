# Vulnerability: Using latest tag instead of specific version
FROM node:latest

# Vulnerability: Running as root user (no USER directive)
# Vulnerability: Hardcoded credentials
ENV DB_PASSWORD=admin123
ENV API_KEY=sk-1234567890abcdef

# Vulnerability: Exposing unnecessary ports
EXPOSE 22 3306 5432 8080

# Vulnerability: Installing unnecessary packages
RUN apt-get update && apt-get install -y \
    telnet \
    ftp \
    netcat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Vulnerability: Copying entire directory including sensitive files
COPY . .

# Vulnerability: Running package install as root
RUN npm install

# Vulnerability: chmod 777 - overly permissive permissions
RUN chmod -R 777 /app

# Vulnerability: Using shell form (allows shell injection)
CMD npm start

# Missing: HEALTHCHECK directive
# Missing: Security scanning in build process
# Missing: Minimal base image usage