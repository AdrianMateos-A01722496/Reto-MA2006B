#!/bin/bash

# Para correr en linux / mac: chmod +x generar_claves.sh && ./generar_claves.sh
# Para correr en windows: powershell -ExecutionPolicy Bypass -File generar_claves.sh

echo "Generando clave privada..."
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

echo "Generando clave pública..."
openssl rsa -in private_key.pem -pubout -out public_key.pem

echo "¡Claves generadas exitosamente!"
echo "Clave privada: private_key.pem"
echo "Clave pública: public_key.pem"