# Case 02: Cloud Data Protection & Applied Cryptography
Verified Completion: [TryHackMe - Introduction to Cryptography]
<img width="1920" height="1080" alt="Снимок экрана (311)" src="https://github.com/user-attachments/assets/614fabd0-8624-4866-bcd4-0623a9b9950e" />



# AWS Cloud Security Best Practices: Applied Cryptography

**Author:** Security Professional  
**Certification:** TryHackMe - Introduction to Cryptography (Completed)  
**Date:** February 14, 2026  
**Version:** 1.0

---

## Executive Summary

This document demonstrates the practical application of fundamental cryptographic principles to secure Amazon Web Services (AWS) cloud infrastructure. Drawing from mastery of symmetric and asymmetric encryption, hashing algorithms, Public Key Infrastructure (PKI), and SSL/TLS protocols, this guide provides actionable security implementations for enterprise cloud environments.

**Core Competencies Demonstrated:**
- Symmetric Encryption (AES-256, AES-128)
- Asymmetric Encryption (RSA, Diffie-Hellman Key Exchange)
- Cryptographic Hashing (SHA-256, SHA-512, HMAC)
- Public Key Infrastructure (PKI) and Certificate Management
- Transport Layer Security (SSL/TLS 1.2, TLS 1.3)
- AWS Key Management Service (KMS) and encryption at rest/in transit

---

## Table of Contents

1. [Cryptographic Fundamentals Review](#1-cryptographic-fundamentals-review)
2. [AWS Encryption Architecture](#2-aws-encryption-architecture)
3. [Data at Rest Protection](#3-data-at-rest-protection)
4. [Data in Transit Protection](#4-data-in-transit-protection)
5. [Key Management Best Practices](#5-key-management-best-practices)
6. [Identity and Access Security](#6-identity-and-access-security)
7. [Compliance and Governance](#7-compliance-and-governance)
8. [Implementation Examples](#8-implementation-examples)
9. [Monitoring and Incident Response](#9-monitoring-and-incident-response)
10. [Conclusion](#10-conclusion)

---

## 1. Cryptographic Fundamentals Review

### 1.1 Symmetric Encryption

**Principle:** Single shared key for both encryption and decryption

**Primary Algorithm: AES (Advanced Encryption Standard)**
- **AES-256**: 256-bit key length, 14 rounds of transformation
- **AES-128**: 128-bit key length, 10 rounds of transformation
- **Block Size**: 128 bits
- **Modes of Operation**: CBC, GCM (Galois/Counter Mode - provides authentication)

**Advantages:**
- Fast encryption/decryption performance
- Efficient for large data volumes
- Low computational overhead

**Limitations:**
- Key distribution challenge (must securely share the key)
- Key compromise exposes all encrypted data
- Not suitable for scenarios requiring non-repudiation

**AWS Applications:**
- Amazon EBS volume encryption
- Amazon S3 server-side encryption (SSE-S3, SSE-KMS)
- Amazon RDS database encryption
- AWS Secrets Manager encrypted secrets

---

### 1.2 Asymmetric Encryption

**Principle:** Public/private key pair - encrypt with public key, decrypt with private key

**Primary Algorithms:**
- **RSA (Rivest-Shamir-Adleman)**: 2048-bit to 4096-bit keys
- **Elliptic Curve Cryptography (ECC)**: Shorter keys, equivalent security
- **Diffie-Hellman**: Key exchange protocol for establishing shared secrets

**Key Exchange Process (Diffie-Hellman):**
```
1. Alice and Bob agree on public parameters (p, g)
2. Alice generates private key (a), computes public key: A = g^a mod p
3. Bob generates private key (b), computes public key: B = g^b mod p
4. Alice computes shared secret: s = B^a mod p
5. Bob computes shared secret: s = A^b mod p
6. Both parties now share the same secret without transmitting it
```

**Advantages:**
- Secure key exchange over insecure channels
- Digital signatures provide non-repudiation
- No need to pre-share secrets

**Limitations:**
- Computationally expensive (50-100x slower than symmetric)
- Not practical for encrypting large data volumes
- Vulnerable to quantum computing (future threat)

**AWS Applications:**
- AWS Certificate Manager (ACM) - RSA and ECC certificates
- SSH key pairs for EC2 instance access
- SSL/TLS certificate private keys
- AWS KMS asymmetric keys for digital signatures
- CloudFront signed URLs and cookies

---

### 1.3 Cryptographic Hashing

**Principle:** One-way function producing fixed-size output (digest) from variable input

**Primary Algorithms:**
- **SHA-256 (Secure Hash Algorithm)**: 256-bit output, part of SHA-2 family
- **SHA-512**: 512-bit output, enhanced security
- **HMAC (Hash-based Message Authentication Code)**: Hashing with secret key

**Properties:**
- **Deterministic**: Same input always produces same output
- **Pre-image Resistance**: Cannot derive input from hash
- **Collision Resistance**: Extremely difficult to find two inputs with same hash
- **Avalanche Effect**: Small input change drastically changes output

**Example - SHA-256 Hash:**
```
Input:  "Hello, AWS Security"
SHA-256: 8f3d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e

Input:  "Hello, AWS Security!" (added exclamation)
SHA-256: 7e2c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

**AWS Applications:**
- S3 object integrity verification (ETag for single-part uploads)
- CloudTrail log file integrity validation
- AWS Artifact checksums
- Lambda function code integrity
- Password storage in RDS/DynamoDB (with salting)
- Git commit verification in CodeCommit

---

### 1.4 Public Key Infrastructure (PKI)

**Components:**
- **Certificate Authority (CA)**: Issues and signs digital certificates
- **Registration Authority (RA)**: Verifies certificate requests
- **Certificate Repository**: Stores issued certificates
- **Certificate Revocation List (CRL)**: Lists revoked certificates

**X.509 Certificate Structure:**
```
Certificate:
    Version: 3
    Serial Number: 5a:3f:9c:...
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=Amazon Root CA 1, O=Amazon
    Validity:
        Not Before: Jan 1 00:00:00 2025 GMT
        Not After:  Jan 1 23:59:59 2026 GMT
    Subject: CN=example.com
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
        RSA Public Key: (2048 bit)
    X509v3 Extensions:
        X509v3 Subject Alternative Name:
            DNS:example.com, DNS:*.example.com
```

**Certificate Chain of Trust:**
```
Root CA (self-signed)
    ↓
Intermediate CA (signed by Root CA)
    ↓
End-Entity Certificate (signed by Intermediate CA)
```

**AWS Applications:**
- AWS Certificate Manager (ACM) for SSL/TLS certificates
- AWS Private CA for internal PKI
- IoT device certificates for authentication
- VPN certificates for secure connectivity

---

### 1.5 SSL/TLS Protocol

**Purpose:** Secure communication channel over untrusted networks

**TLS Handshake Process:**
```
Client                                              Server
  |                                                   |
  |-------- ClientHello (supported ciphers) -------->|
  |                                                   |
  |<------- ServerHello (selected cipher) -----------|
  |<----------- Certificate (X.509) -----------------|
  |<------- ServerKeyExchange (DH params) -----------|
  |<------------ ServerHelloDone -------------------|
  |                                                   |
  |------- ClientKeyExchange (encrypted pre-master)--|
  |------- ChangeCipherSpec -----------------------|
  |------- Finished (encrypted) --------------------|
  |                                                   |
  |<------ ChangeCipherSpec --------------------------|
  |<------ Finished (encrypted) ---------------------|
  |                                                   |
  |======== Encrypted Application Data =============>|
```

**Key Components:**
1. **Authentication**: Server proves identity with certificate
2. **Key Exchange**: Establish shared secret using Diffie-Hellman
3. **Encryption**: Use symmetric encryption (AES) for data transfer
4. **Integrity**: HMAC ensures message hasn't been tampered with

**Cipher Suite Example:**
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

Breakdown:
- TLS: Protocol version
- ECDHE: Elliptic Curve Diffie-Hellman Ephemeral (key exchange)
- RSA: Authentication algorithm
- AES_256_GCM: Symmetric encryption (256-bit AES in GCM mode)
- SHA384: Hashing algorithm for message integrity
```

**TLS Versions:**
- **TLS 1.0/1.1**: Deprecated (vulnerable to POODLE, BEAST attacks)
- **TLS 1.2**: Currently acceptable, widely supported
- **TLS 1.3**: Recommended - faster handshake, stronger security

**AWS Applications:**
- CloudFront HTTPS distribution
- Application Load Balancer (ALB) SSL/TLS termination
- API Gateway custom domains
- RDS encrypted connections
- All AWS API endpoints (https://*)

---

## 2. AWS Encryption Architecture

### 2.1 Defense in Depth Strategy

AWS security follows a multi-layered approach combining multiple cryptographic techniques:

```
┌─────────────────────────────────────────────────────────┐
│ Application Layer                                       │
│ - SSL/TLS (Application ↔ ALB)                          │
│ - API Authentication (AWS Signature v4)                 │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Transport Layer                                         │
│ - VPC Encryption (optional)                            │
│ - VPN/Direct Connect Encryption                        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Storage Layer                                           │
│ - EBS Encryption (AES-256)                             │
│ - S3 Server-Side Encryption (SSE)                      │
│ - RDS Encrypted at Rest                                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Key Management Layer                                    │
│ - AWS KMS (FIPS 140-2 validated HSMs)                  │
│ - Automatic Key Rotation                               │
│ - Envelope Encryption                                  │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Shared Responsibility Model

**AWS Responsibilities:**
- Physical security of data centers
- Hardware encryption modules (HSMs)
- Network infrastructure encryption
- Hypervisor isolation

**Customer Responsibilities:**
- Enable encryption services
- Manage encryption keys
- Configure SSL/TLS policies
- Implement application-level encryption
- Access control and IAM policies

---

## 3. Data at Rest Protection

### 3.1 Amazon EBS Volume Encryption

**Encryption Method:** AES-256 symmetric encryption

**How It Works:**
1. Customer creates encrypted EBS volume via AWS Console/API
2. AWS KMS generates Data Encryption Key (DEK)
3. DEK is encrypted by Customer Master Key (CMK) - **Envelope Encryption**
4. Encrypted DEK stored with volume metadata
5. All data blocks encrypted before writing to physical storage
6. Transparent to applications - encryption/decryption handled by hypervisor

**Envelope Encryption Process:**
```
┌──────────────────────────────────────────────────────┐
│ AWS KMS - Customer Master Key (CMK)                  │
│ - Stored in FIPS 140-2 Level 2 HSMs                 │
│ - Never leaves AWS KMS unencrypted                  │
└──────────────────────────────────────────────────────┘
                      ↓ Encrypts
┌──────────────────────────────────────────────────────┐
│ Data Encryption Key (DEK) - Plaintext               │
│ - Generated by AWS KMS                              │
│ - Used to encrypt actual data                       │
└──────────────────────────────────────────────────────┘
                      ↓
┌──────────────────────────────────────────────────────┐
│ Data Encryption Key (DEK) - Encrypted               │
│ - Stored with volume metadata                       │
└──────────────────────────────────────────────────────┘

When data needs to be read:
1. Encrypted DEK retrieved from metadata
2. AWS KMS decrypts DEK using CMK
3. Plaintext DEK decrypts data blocks
4. Plaintext DEK discarded after use
```

**Benefits of Envelope Encryption:**
- CMK never leaves KMS (highest security)
- Fast encryption of large datasets (DEK used locally)
- Easy key rotation (only CMK needs rotation, not all data)
- Reduced KMS API calls (better performance)

**Terraform Implementation:**
```hcl
# Create KMS key for EBS encryption
resource "aws_kms_key" "ebs_encryption" {
  description             = "KMS key for EBS volume encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true  # Automatic annual rotation

  tags = {
    Name        = "ebs-encryption-key"
    Purpose     = "Data-at-rest protection"
    Algorithm   = "AES-256"
    Compliance  = "HIPAA-PCI-GDPR"
  }
}

resource "aws_kms_alias" "ebs_encryption" {
  name          = "alias/ebs-encryption"
  target_key_id = aws_kms_key.ebs_encryption.key_id
}

# Enable EBS encryption by default
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "default" {
  key_arn = aws_kms_key.ebs_encryption.arn
}

# Create encrypted EBS volume
resource "aws_ebs_volume" "secure_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_encryption.arn

  tags = {
    Name      = "production-encrypted-volume"
    Encrypted = "AES-256"
  }
}

# Launch EC2 with encrypted root volume
resource "aws_instance" "secure_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    kms_key_id            = aws_kms_key.ebs_encryption.arn
    delete_on_termination = true
  }

  tags = {
    Name = "secure-encrypted-instance"
  }
}
```

**Security Best Practices:**
- ✅ Enable EBS encryption by default for entire AWS account
- ✅ Use customer-managed CMKs (not AWS-managed) for audit control
- ✅ Enable automatic key rotation annually
- ✅ Implement least-privilege IAM policies for KMS access
- ✅ Monitor KMS API calls via CloudTrail
- ✅ Encrypt EBS snapshots (automatically encrypted if source is encrypted)

---

### 3.2 Amazon S3 Server-Side Encryption

**Encryption Options:**

#### **SSE-S3 (S3-Managed Keys)**
- **Algorithm:** AES-256
- **Key Management:** AWS manages all keys automatically
- **Use Case:** Simple encryption without key management overhead
- **Header:** `x-amz-server-side-encryption: AES256`

**How SSE-S3 Works:**
```
1. Client uploads object via HTTPS
2. S3 generates unique data key for each object
3. Object encrypted with AES-256 before storage
4. Data key encrypted by S3 master key
5. Encrypted data key stored with object metadata
```

#### **SSE-KMS (KMS-Managed Keys)**
- **Algorithm:** AES-256
- **Key Management:** Customer controls CMK in AWS KMS
- **Benefits:** 
  - Audit trail via CloudTrail
  - Key rotation control
  - Fine-grained access control
- **Header:** `x-amz-server-side-encryption: aws:kms`

**SSE-KMS Envelope Encryption:**
```
┌─────────────────────────────────────────────┐
│ AWS KMS - Customer Master Key (CMK)         │
└─────────────────────────────────────────────┘
                    ↓ Encrypts
┌─────────────────────────────────────────────┐
│ S3 Data Key (unique per object)             │
└─────────────────────────────────────────────┘
                    ↓ Encrypts
┌─────────────────────────────────────────────┐
│ S3 Object Data                              │
└─────────────────────────────────────────────┘
```

#### **SSE-C (Customer-Provided Keys)**
- **Algorithm:** AES-256
- **Key Management:** Customer provides key with each request
- **Use Case:** External key management systems
- **Limitation:** Key must be sent with every request (HTTPS required)

**Terraform Implementation:**
```hcl
# Create KMS key for S3 encryption
resource "aws_kms_key" "s3_encryption" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::ACCOUNT_ID:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create S3 bucket with encryption
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-encrypted-bucket-2026"

  tags = {
    Name       = "Secure Storage"
    Encryption = "AES-256-KMS"
  }
}

# Enable default encryption with SSE-KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_encryption.arn
    }
    bucket_key_enabled = true  # Reduces KMS costs
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for data protection
resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enforce encryption in bucket policy
resource "aws_s3_bucket_policy" "enforce_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
```

**S3 Bucket Keys Feature:**
- Reduces KMS request costs by up to 99%
- S3 uses bucket-level key to generate object keys
- Instead of calling KMS for each object, uses bucket key for batches
- Transparent to applications

**Security Best Practices:**
- ✅ Enable default bucket encryption (SSE-KMS preferred)
- ✅ Use bucket policies to deny unencrypted uploads
- ✅ Enforce HTTPS-only access (TLS in transit)
- ✅ Enable S3 Object Lock for immutable backups
- ✅ Use S3 Access Points for granular access control
- ✅ Enable CloudTrail logging for all S3 API calls

---

### 3.3 Amazon RDS Database Encryption

**Encryption Method:** AES-256 encryption at storage layer

**What Gets Encrypted:**
- Database storage volumes
- Automated backups
- Read replicas
- Snapshots
- Database logs

**Limitations:**
- Cannot enable encryption on existing unencrypted DB instance
- Must create encrypted snapshot and restore to new encrypted instance

**Terraform Implementation:**
```hcl
# Create KMS key for RDS encryption
resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS database encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name    = "rds-encryption-key"
    Service = "RDS"
  }
}

# Create encrypted RDS instance
resource "aws_db_instance" "secure_database" {
  identifier        = "secure-production-db"
  engine            = "postgres"
  engine_version    = "15.3"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_encryption.arn

  db_name  = "appdb"
  username = "admin"
  password = random_password.db_password.result  # Use secure password

  # Network security
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false

  # Backup configuration
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  # Enable encryption in transit
  ca_cert_identifier = "rds-ca-rsa2048-g1"

  # Deletion protection
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "secure-db-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  tags = {
    Name       = "Production Database"
    Encrypted  = "AES-256"
    Compliance = "HIPAA-PCI"
  }
}

# Secure password generation
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Store password in AWS Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "production/database/master_password"
  recovery_window_in_days = 30
  kms_key_id              = aws_kms_key.rds_encryption.arn
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = aws_db_instance.secure_database.username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.secure_database.endpoint
    port     = 5432
    dbname   = aws_db_instance.secure_database.db_name
  })
}
```

**Connection Encryption (TLS):**
```python
# Python application connecting with SSL/TLS
import psycopg2

# Download RDS CA certificate
# wget https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

conn = psycopg2.connect(
    host="database.region.rds.amazonaws.com",
    port=5432,
    database="appdb",
    user="admin",
    password="secure_password",
    sslmode="verify-full",  # Enforce TLS with certificate verification
    sslrootcert="/path/to/global-bundle.pem"
)
```

**Security Best Practices:**
- ✅ Always enable storage encryption for production databases
- ✅ Use SSL/TLS for client connections (enforce with parameter group)
- ✅ Rotate credentials regularly using Secrets Manager
- ✅ Enable automated backups with encryption
- ✅ Use IAM database authentication instead of passwords
- ✅ Implement least-privilege database user permissions

---

### 3.4 Additional AWS Services Encryption

#### **Amazon DynamoDB**
- **Encryption:** AES-256 at rest (automatic)
- **Key Options:** AWS-managed or customer-managed CMK
- **In-Transit:** All communications over TLS

```hcl
resource "aws_dynamodb_table" "secure_table" {
  name           = "SecureUserData"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_encryption.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name       = "Encrypted User Table"
    Encryption = "KMS"
  }
}
```

#### **AWS Lambda Environment Variables**
- **Encryption:** KMS-encrypted at rest
- **Best Practice:** Use for database credentials, API keys

```hcl
resource "aws_lambda_function" "secure_function" {
  filename         = "function.zip"
  function_name    = "secure-processor"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  
  environment {
    variables = {
      DB_HOST     = aws_db_instance.secure_database.endpoint
      SECRET_ARN  = aws_secretsmanager_secret.db_password.arn
    }
  }

  kms_key_arn = aws_kms_key.lambda_encryption.arn

  tags = {
    Security = "Encrypted-Variables"
  }
}
```

#### **Amazon EFS (Elastic File System)**
- **Encryption:** AES-256 at rest and in transit
- **Transport Encryption:** TLS 1.2

```hcl
resource "aws_efs_file_system" "secure_efs" {
  encrypted  = true
  kms_key_id = aws_kms_key.efs_encryption.arn

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name       = "Secure File System"
    Encryption = "AES-256"
  }
}
```

---

## 4. Data in Transit Protection

### 4.1 SSL/TLS Configuration for AWS Services

#### **Application Load Balancer (ALB) with TLS Termination**

**Architecture:**
```
Internet (HTTPS/TLS) → ALB (TLS Termination) → EC2 Instances (HTTP)
```

**Benefits:**
- Centralized certificate management
- Offload encryption processing from application servers
- Easy certificate rotation

**Terraform Implementation:**
```hcl
# Request SSL/TLS certificate from ACM
resource "aws_acm_certificate" "web_app" {
  domain_name               = "www.example.com"
  subject_alternative_names = ["example.com", "*.example.com"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "Web Application Certificate"
  }
}

# DNS validation records (if using Route53)
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.web_app.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "web_app" {
  certificate_arn         = aws_acm_certificate.web_app.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Create Application Load Balancer
resource "aws_lb" "web_app" {
  name               = "secure-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = true
  enable_http2              = true
  enable_cross_zone_load_balancing = true

  tags = {
    Name = "Secure Web ALB"
  }
}

# HTTPS Listener with TLS 1.2+ enforcement
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web_app.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"  # TLS 1.2 & 1.3 only
  certificate_arn   = aws_acm_certificate.web_app.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_app.arn
  }
}

# HTTP to HTTPS redirect
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.web_app.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"  # Permanent redirect
    }
  }
}

# Target group for EC2 instances
resource "aws_lb_target_group" "web_app" {
  name     = "web-app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
  }

  tags = {
    Name = "Web App Target Group"
  }
}
```

**SSL/TLS Policy Selection:**

| Policy Name | TLS Version | Cipher Suites | Use Case |
|------------|------------|---------------|----------|
| `ELBSecurityPolicy-TLS13-1-2-2021-06` | TLS 1.2, 1.3 | Modern, secure | **Recommended** - New applications |
| `ELBSecurityPolicy-TLS-1-2-2017-01` | TLS 1.2 | Balanced | Legacy client support |
| `ELBSecurityPolicy-FS-1-2-Res-2020-10` | TLS 1.2 | Forward secrecy | High security |

**Recommended Cipher Suites (TLS 1.3):**
- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

---

### 4.2 CloudFront with HTTPS

**CloudFront + S3 Secure Architecture:**
```
User (HTTPS/TLS 1.3) 
    ↓
CloudFront Edge Location (TLS Termination)
    ↓
S3 Origin (HTTPS with OAI authentication)
```

**Terraform Implementation:**
```hcl
# S3 bucket for static website
resource "aws_s3_bucket" "website" {
  bucket = "my-secure-website-2026"
}

resource "aws_s3_bucket_public_access_block" "website" {
  bucket = aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudFront Origin Access Identity (OAI)
resource "aws_cloudfront_origin_access_identity" "website" {
  comment = "OAI for secure website"
}

# S3 bucket policy allowing only CloudFront access
resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOAI"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.website.iam_arn
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.website.arn}/*"
      }
    ]
  })
}

# CloudFront distribution with HTTPS
resource "aws_cloudfront_distribution" "website" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = ["www.example.com"]

  origin {
    domain_name = aws_s3_bucket.website.bucket_regional_domain_name
    origin_id   = "S3-Website"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.website.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-Website"
    viewer_protocol_policy = "redirect-to-https"  # Force HTTPS
    compress               = true
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  # TLS configuration
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cloudfront.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"  # TLS 1.2+ only
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # Security headers
  custom_error_response {
    error_code         = 404
    response_code      = 404
    response_page_path = "/404.html"
  }

  tags = {
    Name     = "Secure Website Distribution"
    Protocol = "HTTPS-Only"
  }
}

# ACM certificate (must be in us-east-1 for CloudFront)
resource "aws_acm_certificate" "cloudfront" {
  provider                  = aws.us_east_1
  domain_name               = "www.example.com"
  subject_alternative_names = ["example.com"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}
```

**Security Headers with Lambda@Edge:**
```javascript
// Add security headers to CloudFront responses
exports.handler = async (event) => {
    const response = event.Records[0].cf.response;
    const headers = response.headers;

    // Enforce HTTPS
    headers['strict-transport-security'] = [{
        key: 'Strict-Transport-Security',
        value: 'max-age=31536000; includeSubDomains; preload'
    }];

    // Prevent clickjacking
    headers['x-frame-options'] = [{
        key: 'X-Frame-Options',
        value: 'DENY'
    }];

    // Content Security Policy
    headers['content-security-policy'] = [{
        key: 'Content-Security-Policy',
        value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }];

    return response;
};
```

---

### 4.3 VPN and VPC Encryption

#### **AWS Site-to-Site VPN**
- **Encryption:** IPsec with AES-256
- **Authentication:** Pre-shared keys or certificates
- **Perfect Forward Secrecy:** Diffie-Hellman groups 14-24

```hcl
resource "aws_vpn_connection" "main" {
  vpn_gateway_id      = aws_vpn_gateway.main.id
  customer_gateway_id = aws_customer_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = false

  # IPsec configuration
  tunnel1_ike_versions                 = ["ikev2"]
  tunnel1_phase1_dh_group_numbers      = [14, 15, 16, 17, 18, 19, 20, 21]
  tunnel1_phase1_encryption_algorithms = ["AES256", "AES256-GCM-16"]
  tunnel1_phase1_integrity_algorithms  = ["SHA2-256", "SHA2-384", "SHA2-512"]
  tunnel1_phase2_dh_group_numbers      = [14, 15, 16, 17, 18, 19, 20, 21]
  tunnel1_phase2_encryption_algorithms = ["AES256", "AES256-GCM-16"]
  tunnel1_phase2_integrity_algorithms  = ["SHA2-256", "SHA2-384", "SHA2-512"]

  tags = {
    Name       = "Secure VPN Connection"
    Encryption = "IPsec-AES-256"
  }
}
```

#### **AWS Client VPN (OpenVPN)**
- **Encryption:** TLS 1.2+
- **Authentication:** Certificate-based or Active Directory
- **Protocol:** UDP 443 or TCP 443

---

### 4.4 API Gateway with TLS

```hcl
# API Gateway with custom domain and TLS
resource "aws_api_gateway_rest_api" "secure_api" {
  name        = "SecureAPI"
  description = "API with TLS 1.2+ enforcement"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_domain_name" "api" {
  domain_name              = "api.example.com"
  regional_certificate_arn = aws_acm_certificate.api.arn

  security_policy = "TLS_1_2"  # Enforce TLS 1.2+

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# Enforce HTTPS only (no HTTP)
resource "aws_api_gateway_method" "secure_method" {
  rest_api_id   = aws_api_gateway_rest_api.secure_api.id
  resource_id   = aws_api_gateway_resource.resource.id
  http_method   = "POST"
  authorization = "AWS_IAM"  # Require AWS Signature v4

  request_parameters = {
    "method.request.header.X-Forwarded-Proto" = true
  }
}
```

---

## 5. Key Management Best Practices

### 5.1 AWS Key Management Service (KMS) Architecture

**KMS Hierarchy:**
```
┌────────────────────────────────────────────────────┐
│ AWS KMS - Hardware Security Modules (HSMs)         │
│ - FIPS 140-2 Level 2 validated                    │
│ - Multi-tenant, managed by AWS                    │
└────────────────────────────────────────────────────┘
                      ↓
┌────────────────────────────────────────────────────┐
│ Customer Master Keys (CMKs)                        │
│ - AWS Managed: Automatic rotation                 │
│ - Customer Managed: Full control                  │
│ - Asymmetric: RSA, ECC for signing/verification   │
└────────────────────────────────────────────────────┘
                      ↓
┌────────────────────────────────────────────────────┐
│ Data Encryption Keys (DEKs)                        │
│ - Generated by KMS using CMK                      │
│ - Used locally for actual encryption              │
│ - Never stored unencrypted                        │
└────────────────────────────────────────────────────┘
```

### 5.2 Key Rotation Strategy

**Automatic Key Rotation (AWS KMS):**
- Enabled via `enable_key_rotation = true`
- Rotates backing key every 365 days automatically
- Previous key versions retained for decryption
- Transparent to applications (same CMK ARN)

```hcl
resource "aws_kms_key" "auto_rotate" {
  description             = "Key with automatic rotation"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name            = "Auto-Rotated Key"
    RotationEnabled = "true"
  }
}

# Monitor key usage
resource "aws_cloudwatch_metric_alarm" "kms_key_usage" {
  alarm_name          = "kms-key-high-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "UserErrorCount"
  namespace           = "AWS/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Alert on KMS key errors"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    KeyId = aws_kms_key.auto_rotate.key_id
  }
}
```

**Manual Key Rotation (Application Keys):**
```python
# Python script for manual key rotation
import boto3
from datetime import datetime, timedelta

def rotate_application_key():
    kms = boto3.client('kms')
    
    # Create new CMK
    new_key = kms.create_key(
        Description='Rotated Application Key',
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS'
    )
    
    # Create alias pointing to new key
    alias_name = 'alias/application-key'
    kms.update_alias(
        AliasName=alias_name,
        TargetKeyId=new_key['KeyMetadata']['KeyId']
    )
    
    print(f"Key rotated successfully. New Key ID: {new_key['KeyMetadata']['KeyId']}")
    
    # Schedule old key for deletion (30 days)
    # old_key_id = '...'
    # kms.schedule_key_deletion(KeyId=old_key_id, PendingWindowInDays=30)

rotate_application_key()
```

### 5.3 Key Policies and Access Control

**Principle of Least Privilege:**
```hcl
resource "aws_kms_key" "restricted_key" {
  description = "Restricted access key"

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-policy-1"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::ACCOUNT_ID:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Application Role Encrypt/Decrypt"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::ACCOUNT_ID:role/ApplicationRole"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.us-east-1.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:us-east-1:ACCOUNT_ID:log-group:*"
          }
        }
      },
      {
        Sid    = "Prevent Key Deletion by Non-Admins"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteAlias"
        ]
        Resource = "*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = "arn:aws:iam::ACCOUNT_ID:role/SecurityAdmin"
          }
        }
      }
    ]
  })
}
```

### 5.4 Multi-Region Keys

**Use Case:** Disaster recovery, global applications

```hcl
# Primary key in us-east-1
resource "aws_kms_key" "primary" {
  description             = "Primary multi-region key"
  multi_region            = true
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = {
    Name = "Primary Multi-Region Key"
  }
}

# Replica key in eu-west-1
resource "aws_kms_replica_key" "replica" {
  provider                = aws.eu_west_1
  description             = "Replica key in Europe"
  primary_key_arn         = aws_kms_key.primary.arn
  deletion_window_in_days = 30

  tags = {
    Name = "Replica Multi-Region Key"
  }
}
```

**Benefits:**
- Encrypt in one region, decrypt in another
- Low-latency access to encrypted data globally
- Disaster recovery without re-encrypting data

---

## 6. Identity and Access Security

### 6.1 AWS Signature Version 4 (SigV4)

**Purpose:** Authenticate and authorize AWS API requests using HMAC-SHA256

**Signing Process:**
```
1. Create Canonical Request (standardized format)
   - HTTP method, URI, query string, headers, payload hash
   
2. Create String to Sign
   - Algorithm (AWS4-HMAC-SHA256)
   - Timestamp
   - Credential scope
   - Hash of canonical request

3. Calculate Signature
   - Derive signing key from secret access key
   - HMAC-SHA256 of string to sign

4. Add Authorization Header
   - Algorithm, credentials, signed headers, signature
```

**Example Signature Calculation (Python):**
```python
import hmac
import hashlib
from datetime import datetime

def sign_aws_request(secret_key, date_stamp, region, service, string_to_sign):
    """Calculate AWS Signature Version 4"""
    # Step 1: Derive signing key
    k_date = hmac.new(
        f"AWS4{secret_key}".encode('utf-8'),
        date_stamp.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    k_region = hmac.new(
        k_date,
        region.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    k_service = hmac.new(
        k_region,
        service.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    k_signing = hmac.new(
        k_service,
        "aws4_request".encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    # Step 2: Calculate signature
    signature = hmac.new(
        k_signing,
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return signature

# Example usage
secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
date_stamp = "20260214"
region = "us-east-1"
service = "s3"
string_to_sign = "AWS4-HMAC-SHA256\n20260214T120000Z\n..."

signature = sign_aws_request(secret_key, date_stamp, region, service, string_to_sign)
print(f"Signature: {signature}")
```

**Authorization Header Format:**
```
Authorization: AWS4-HMAC-SHA256 
Credential=AKIAIOSFODNN7EXAMPLE/20260214/us-east-1/s3/aws4_request,
SignedHeaders=host;x-amz-date,
Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7
```

**Security Properties:**
- **Message Integrity:** HMAC ensures request hasn't been tampered with
- **Authentication:** Proves request comes from account with valid credentials
- **Replay Protection:** Timestamp validation prevents replay attacks
- **Non-repudiation:** Digital signature proves originator

### 6.2 IAM Policies for Encryption

**Enforce Encryption in IAM Policies:**
```hcl
# IAM policy requiring S3 encryption
resource "aws_iam_policy" "enforce_s3_encryption" {
  name        = "EnforceS3Encryption"
  description = "Deny unencrypted S3 uploads"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Action = "s3:PutObject"
        Resource = "arn:aws:s3:::*/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = ["AES256", "aws:kms"]
          }
        }
      },
      {
        Sid    = "RequireSecureTransport"
        Effect = "Deny"
        Action = "s3:*"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# IAM policy for KMS key usage
resource "aws_iam_policy" "kms_usage" {
  name        = "KMSEncryptDecrypt"
  description = "Allow encrypt/decrypt with specific KMS key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKMSUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.application_key.arn
      }
    ]
  })
}
```

---

## 7. Compliance and Governance

### 7.1 Compliance Framework Mapping

| Framework | Cryptography Requirements | AWS Services |
|-----------|--------------------------|--------------|
| **HIPAA** | Encrypt PHI at rest and in transit (§164.312(a)(2)(iv)) | KMS, S3 SSE, EBS encryption, TLS |
| **PCI-DSS** | Encrypt cardholder data (Req 3.4, 4.1) | KMS, RDS encryption, TLS 1.2+ |
| **GDPR** | Appropriate security measures (Art. 32) | All encryption services |
| **SOC 2** | Encryption controls (CC6.7) | KMS, encryption at rest/transit |
| **FedRAMP** | FIPS 140-2 validated cryptography | KMS (FIPS 140-2 Level 2) |
| **ISO 27001** | Cryptographic controls (A.10.1.1) | All AWS encryption |

### 7.2 Encryption Compliance Monitoring

**AWS Config Rules for Compliance:**
```hcl
# Enable AWS Config
resource "aws_config_configuration_recorder" "main" {
  name     = "compliance-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }
}

# S3 bucket encryption check
resource "aws_config_config_rule" "s3_encryption" {
  name = "s3-bucket-server-side-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# EBS encryption check
resource "aws_config_config_rule" "ebs_encryption" {
  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}

# RDS encryption check
resource "aws_config_config_rule" "rds_encryption" {
  name = "rds-storage-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
}

# TLS version check for ALB
resource "aws_config_config_rule" "alb_tls" {
  name = "alb-http-to-https-redirection-check"

  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
  }
}

# CloudTrail log encryption
resource "aws_config_config_rule" "cloudtrail_encryption" {
  name = "cloud-trail-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }
}
```

**Security Hub Compliance Standards:**
```hcl
# Enable Security Hub
resource "aws_securityhub_account" "main" {}

# CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

# PCI-DSS
resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"
}

# AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
}
```

### 7.3 Audit Logging for Cryptographic Operations

**CloudTrail Logging for KMS:**
```hcl
resource "aws_cloudtrail" "kms_audit" {
  name                          = "kms-encryption-audit"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail_encryption.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::KMS::Key"
      values = ["arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"]
    }
  }

  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = ["${aws_s3_bucket.sensitive_data.arn}/*"]
    }
  }

  tags = {
    Name    = "KMS Audit Trail"
    Purpose = "Compliance-Encryption-Monitoring"
  }
}
```

**Important KMS CloudTrail Events:**
- `Decrypt` - Key used to decrypt data
- `Encrypt` - Key used to encrypt data
- `GenerateDataKey` - DEK generation for envelope encryption
- `CreateKey` - New CMK created
- `ScheduleKeyDeletion` - Key marked for deletion
- `DisableKey` - Key disabled
- `PutKeyPolicy` - Key policy modified

**CloudWatch Alarms for Suspicious Activity:**
```hcl
resource "aws_cloudwatch_log_metric_filter" "kms_key_disabled" {
  name           = "kms-key-disabled"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.eventName = DisableKey || $.eventName = ScheduleKeyDeletion }"

  metric_transformation {
    name      = "KMSKeyDisabled"
    namespace = "Security/KMS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_key_disabled_alarm" {
  alarm_name          = "kms-key-disabled-alert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KMSKeyDisabled"
  namespace           = "Security/KMS"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert when KMS key is disabled or scheduled for deletion"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

---

## 8. Implementation Examples

### 8.1 Complete Secure Application Architecture

**Architecture Diagram:**
```
Internet
   ↓ (HTTPS/TLS 1.3)
CloudFront Distribution
   ↓ (HTTPS)
Application Load Balancer (TLS Termination)
   ↓ (HTTP - Private Subnet)
EC2 Auto Scaling Group
   ↓ (TLS 1.2)
RDS PostgreSQL (Encrypted)
   ↓
EBS Volumes (AES-256 Encrypted)

S3 Bucket (SSE-KMS) ← Application writes logs/files
```

**Complete Terraform Implementation:**
```hcl
# ============================================
# 1. KMS Keys for Different Services
# ============================================

resource "aws_kms_key" "master_key" {
  description             = "Master encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  tags = {
    Name        = "Master Encryption Key"
    Environment = "Production"
  }
}

resource "aws_kms_alias" "master_key" {
  name          = "alias/master-encryption-key"
  target_key_id = aws_kms_key.master_key.key_id
}

# ============================================
# 2. VPC with Private Subnets
# ============================================

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "Secure VPC"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "Private Subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "Public Subnet ${count.index + 1}"
  }
}

# ============================================
# 3. Encrypted RDS Database
# ============================================

resource "aws_db_subnet_group" "main" {
  name       = "main-db-subnet"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "Main DB Subnet Group"
  }
}

resource "aws_security_group" "database" {
  name        = "database-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from application"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Database Security Group"
  }
}

resource "aws_db_instance" "main" {
  identifier     = "secure-app-db"
  engine         = "postgres"
  engine_version = "15.3"
  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 500
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.master_key.arn

  db_name  = "appdb"
  username = "dbadmin"
  password = random_password.db_password.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false

  # SSL/TLS enforcement
  ca_cert_identifier = "rds-ca-rsa2048-g1"

  # Backup configuration
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "secure-app-db-final-snapshot"

  tags = {
    Name       = "Secure Application Database"
    Encrypted  = "AES-256-KMS"
    Compliance = "HIPAA-PCI-GDPR"
  }
}

# ============================================
# 4. Encrypted S3 Bucket
# ============================================

resource "aws_s3_bucket" "application_data" {
  bucket = "secure-app-data-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Application Data Bucket"
    Encryption  = "SSE-KMS"
    Environment = "Production"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.master_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ============================================
# 5. Application Load Balancer with TLS
# ============================================

resource "aws_security_group" "alb" {
  name        = "alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from internet (redirect to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ALB Security Group"
  }
}

resource "aws_lb" "main" {
  name               = "secure-app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = true
  enable_http2              = true

  tags = {
    Name = "Secure Application ALB"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ============================================
# 6. EC2 Launch Template with Encrypted EBS
# ============================================

resource "aws_security_group" "application" {
  name        = "application-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Application Security Group"
  }
}

resource "aws_launch_template" "application" {
  name_prefix   = "secure-app-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.medium"

  iam_instance_profile {
    name = aws_iam_instance_profile.application.name
  }

  vpc_security_group_ids = [aws_security_group.application.id]

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.master_key.arn
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    db_endpoint = aws_db_instance.main.endpoint
    s3_bucket   = aws_s3_bucket.application_data.id
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name      = "Secure Application Instance"
      Encrypted = "AES-256"
    }
  }
}

# ============================================
# 7. Auto Scaling Group
# ============================================

resource "aws_autoscaling_group" "application" {
  name                = "secure-app-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.main.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = 2
  max_size         = 10
  desired_capacity = 2

  launch_template {
    id      = aws_launch_template.application.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "Secure Application Server"
    propagate_at_launch = true
  }
}

# ============================================
# 8. CloudWatch Logs Encryption
# ============================================

resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/application/secure-app"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.master_key.arn

  tags = {
    Name      = "Application Logs"
    Encrypted = "KMS"
  }
}

# ============================================
# 9. Secrets Manager for Credentials
# ============================================

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "production/database/credentials"
  description             = "Database credentials"
  kms_key_id              = aws_kms_key.master_key.arn
  recovery_window_in_days = 30

  tags = {
    Name      = "Database Credentials"
    Encrypted = "KMS"
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.endpoint
    port     = 5432
    dbname   = aws_db_instance.main.db_name
  })
}
```

### 8.2 Application Code - Secure AWS SDK Usage

**Python Application with Encryption:**
```python
import boto3
import json
from botocore.exceptions import ClientError

class SecureAWSClient:
    def __init__(self):
        # AWS SDK automatically uses HTTPS (TLS 1.2+)
        self.s3 = boto3.client('s3')
        self.kms = boto3.client('kms')
        self.secretsmanager = boto3.client('secretsmanager')
        self.rds = boto3.client('rds')
        
    def get_database_credentials(self, secret_name):
        """Retrieve encrypted database credentials from Secrets Manager"""
        try:
            response = self.secretsmanager.get_secret_value(
                SecretId=secret_name
            )
            # Secrets Manager automatically decrypts using KMS
            return json.loads(response['SecretString'])
        except ClientError as e:
            print(f"Error retrieving secret: {e}")
            raise
    
    def upload_encrypted_file(self, bucket_name, file_path, kms_key_id):
        """Upload file to S3 with KMS encryption"""
        try:
            with open(file_path, 'rb') as file:
                self.s3.put_object(
                    Bucket=bucket_name,
                    Key=file_path.split('/')[-1],
                    Body=file,
                    ServerSideEncryption='aws:kms',
                    SSEKMSKeyId=kms_key_id,
                    # Enforce HTTPS (already default in boto3)
                )
            print(f"File uploaded with KMS encryption: {file_path}")
        except ClientError as e:
            print(f"Upload error: {e}")
            raise
    
    def download_and_decrypt_file(self, bucket_name, object_key):
        """Download and automatically decrypt S3 object"""
        try:
            response = self.s3.get_object(
                Bucket=bucket_name,
                Key=object_key
            )
            # Decryption happens automatically using KMS
            content = response['Body'].read()
            
            # Verify encryption was used
            encryption = response.get('ServerSideEncryption')
            kms_key = response.get('SSEKMSKeyId')
            
            print(f"Downloaded file encrypted with: {encryption}")
            print(f"KMS Key ID: {kms_key}")
            
            return content
        except ClientError as e:
            print(f"Download error: {e}")
            raise
    
    def encrypt_data_with_kms(self, kms_key_id, plaintext):
        """Directly encrypt data using KMS"""
        try:
            response = self.kms.encrypt(
                KeyId=kms_key_id,
                Plaintext=plaintext.encode('utf-8')
            )
            # Returns base64-encoded ciphertext
            return response['CiphertextBlob']
        except ClientError as e:
            print(f"Encryption error: {e}")
            raise
    
    def decrypt_data_with_kms(self, ciphertext_blob):
        """Decrypt data using KMS"""
        try:
            response = self.kms.decrypt(
                CiphertextBlob=ciphertext_blob
            )
            # KMS automatically determines which key to use
            return response['Plaintext'].decode('utf-8')
        except ClientError as e:
            print(f"Decryption error: {e}")
            raise
    
    def generate_data_key(self, kms_key_id):
        """Generate data encryption key for envelope encryption"""
        try:
            response = self.kms.generate_data_key(
                KeyId=kms_key_id,
                KeySpec='AES_256'
            )
            return {
                'plaintext': response['Plaintext'],
                'ciphertext': response['CiphertextBlob']
            }
        except ClientError as e:
            print(f"Key generation error: {e}")
            raise

# Usage example
if __name__ == "__main__":
    client = SecureAWSClient()
    
    # Get database credentials
    db_creds = client.get_database_credentials(
        'production/database/credentials'
    )
    
    # Upload encrypted file
    client.upload_encrypted_file(
        bucket_name='my-secure-bucket',
        file_path='/tmp/sensitive-data.csv',
        kms_key_id='arn:aws:kms:us-east-1:123456789012:key/...'
    )
    
    # Encrypt sensitive data
    encrypted = client.encrypt_data_with_kms(
        kms_key_id='alias/master-encryption-key',
        plaintext='Social Security Number: 123-45-6789'
    )
    
    # Decrypt when needed
    decrypted = client.decrypt_data_with_kms(encrypted)
    print(f"Decrypted: {decrypted}")
```

---

## 9. Monitoring and Incident Response

### 9.1 Security Monitoring Dashboard

**CloudWatch Dashboard for Encryption Monitoring:**
```hcl
resource "aws_cloudwatch_dashboard" "encryption_monitoring" {
  dashboard_name = "Encryption-Security-Dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/KMS", "UserErrorCount", { stat = "Sum" }],
            [".", "ThrottleCount", { stat = "Sum" }]
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          title  = "KMS Errors and Throttling"
        }
      },
      {
        type = "log"
        properties = {
          query   = "SOURCE '/aws/cloudtrail' | fields eventTime, eventName, errorCode | filter eventName like /Decrypt|Encrypt|GenerateDataKey/ and errorCode exists | stats count() by eventName, errorCode"
          region  = "us-east-1"
          title   = "KMS API Errors"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/S3", "NumberOfObjects", { stat = "Average" }],
            [".", "BucketSizeBytes", { stat = "Average" }]
          ]
          period = 3600
          stat   = "Average"
          region = "us-east-1"
          title  = "S3 Storage Metrics"
        }
      }
    ]
  })
}
```

### 9.2 Incident Response Playbook

**Scenario: Suspected KMS Key Compromise**

**Immediate Actions (0-1 hour):**
1. **Disable Compromised Key**
   ```bash
   aws kms disable-key --key-id <compromised-key-id>
   ```

2. **Review CloudTrail Logs**
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=<key-arn> \
     --start-time 2026-02-01T00:00:00Z \
     --max-results 1000
   ```

3. **Identify Affected Resources**
   ```bash
   # Find all resources encrypted with this key
   aws resourcegroupstaggingapi get-resources \
     --tag-filters Key=KMSKeyId,Values=<key-id>
   ```

**Short-term Actions (1-24 hours):**
4. **Create New Key**
   ```bash
   aws kms create-key \
     --description "Replacement key after incident" \
     --key-usage ENCRYPT_DECRYPT
   ```

5. **Re-encrypt Data**
   ```python
   # Re-encrypt S3 objects with new key
   import boto3
   
   s3 = boto3.client('s3')
   bucket_name = 'sensitive-data-bucket'
   new_kms_key = 'arn:aws:kms:us-east-1:ACCOUNT:key/NEW_KEY'
   
   objects = s3.list_objects_v2(Bucket=bucket_name)
   for obj in objects.get('Contents', []):
       s3.copy_object(
           Bucket=bucket_name,
           Key=obj['Key'],
           CopySource={'Bucket': bucket_name, 'Key': obj['Key']},
           ServerSideEncryption='aws:kms',
           SSEKMSKeyId=new_kms_key,
           MetadataDirective='COPY'
       )
   ```

6. **Rotate Application Credentials**
   - Update Secrets Manager secrets
   - Restart applications with new credentials

**Long-term Actions (1-7 days):**
7. **Root Cause Analysis**
   - Review IAM policies and permissions
   - Analyze CloudTrail logs for unauthorized access patterns
   - Identify security control gaps

8. **Schedule Old Key Deletion**
   ```bash
   aws kms schedule-key-deletion \
     --key-id <old-key-id> \
     --pending-window-in-days 30
   ```

9. **Update Documentation and Runbooks**

---

## 10. Conclusion

This document demonstrates comprehensive understanding and practical application of cryptographic principles to secure AWS cloud infrastructure:

### Key Takeaways

**1. Encryption at Rest (Symmetric Encryption - AES-256)**
- Applied to EBS volumes, S3 buckets, RDS databases, and DynamoDB tables
- Implemented envelope encryption for performance and security
- Managed keys using AWS KMS with automatic rotation

**2. Encryption in Transit (SSL/TLS Protocol)**
- Enforced TLS 1.2+ for all AWS services
- Implemented certificate management with ACM
- Configured secure cipher suites and perfect forward secrecy

**3. Key Management (AWS KMS)**
- Leveraged FIPS 140-2 validated HSMs
- Implemented least-privilege key policies
- Enabled CloudTrail logging for compliance and auditing

**4. Authentication (Asymmetric Encryption & Hashing)**
- AWS Signature v4 using HMAC-SHA256
- Digital certificates for service authentication
- IAM policies enforcing encryption requirements

**5. Compliance and Governance**
- Mapped controls to HIPAA, PCI-DSS, GDPR, SOC 2
- Automated compliance monitoring with AWS Config and Security Hub
- Established audit trails for all cryptographic operations

### Professional Impact

This document serves as evidence of:
- ✅ Strong foundation in cryptographic theory (TryHackMe certified)
- ✅ Practical implementation skills in cloud environments
- ✅ Understanding of compliance and governance requirements
- ✅ Ability to architect secure, production-ready systems
- ✅ Proficiency with Infrastructure as Code (Terraform)
- ✅ Experience with AWS security services and best practices

### Continuous Learning Path

**Next Steps for Advanced Cryptography:**
1. Quantum-resistant cryptography (NIST post-quantum standards)
2. Hardware Security Modules (CloudHSM) implementation
3. Advanced PKI management and certificate automation
4. Zero-trust architecture with encryption everywhere
5. Homomorphic encryption for processing encrypted data

---

## Appendix: Cryptographic Algorithm Reference

### AES-256 Specifications
- **Type:** Symmetric block cipher
- **Key Length:** 256 bits
- **Block Size:** 128 bits
- **Rounds:** 14
- **Mode:** CBC, GCM (authenticated encryption)
- **Performance:** ~3 GB/s on modern CPUs (hardware-accelerated)

### RSA-2048 Specifications
- **Type:** Asymmetric encryption
- **Key Length:** 2048 bits (minimum), 4096 bits (high security)
- **Algorithm:** Based on integer factorization problem
- **Performance:** ~100x slower than AES
- **Use Case:** Key exchange, digital signatures

### SHA-256 Specifications
- **Type:** Cryptographic hash function
- **Output:** 256 bits (64 hexadecimal characters)
- **Collision Resistance:** 2^128 operations
- **Pre-image Resistance:** 2^256 operations
- **Performance:** ~300 MB/s on modern CPUs

### Diffie-Hellman Parameters
- **Group 14:** 2048-bit modulus
- **Group 19:** 256-bit elliptic curve (secp256r1)
- **Group 20:** 384-bit elliptic curve (secp384r1)
- **Ephemeral:** Keys generated per session (forward secrecy)

---

**Document Status:** FINAL  
**Classification:** Portfolio Document  
**Author Certification:** TryHackMe - Introduction to Cryptography (Completed)  
**Last Updated:** February 14, 2026
