package main

// Generate RSA Private PEM with OpenSSL
// $ openssl genpkey -algorithm RSA -out rsademo-2048.pem -pkeyopt rsa_keygen_bits:2048
// $ openssl genrsa -out rsademo-2048-2.pem 2048
// $ openssl genrsa -out rsademo.pem #1024bits

// Extract RSA PublicKey
// $ openssl rsa -in rsademo-2048.pem -pubout -out rsademo-2048_pub.pem
// $ openssl rsa -in rsademo.pem -pubout -out rsademo_pub.pem
//

// Usage:
// public -pub id_rsa_pub.pem  -data data.txt > data.txt.enc
// private -pk id_rsa.pem -cipher data.txt.enc -pkcs 1
