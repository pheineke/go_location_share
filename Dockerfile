# Build-Stage: Go-Server bauen
FROM golang:1.24.1 AS builder

# Arbeitsverzeichnis setzen
WORKDIR /app

# Repository klonen
RUN git clone "https://github.com/pheineke/go_location_share.git" .

# Abhängigkeiten auflösen
RUN go mod tidy

# Go-Server kompilieren
RUN go build -o server main.go

# Minimalistisches Laufzeit-Image
FROM debian:bullseye-slim

# Arbeitsverzeichnis setzen
WORKDIR /app

# Benötigte Pakete installieren (z. B. für OpenSSL)
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Dateien vom Builder kopieren
COPY --from=builder /app/server /app/
COPY --from=builder /app/ssl_keygen.sh /app/

# SSL-Skript ausführbar machen und ausführen
RUN chmod +x /app/ssl_keygen.sh && /app/ssl_keygen.sh

# Port für den Go-Server freigeben
EXPOSE 1313

# Server starten
CMD ["./server"]
