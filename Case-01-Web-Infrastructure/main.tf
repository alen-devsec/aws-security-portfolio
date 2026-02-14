# WARNING: This is unsafe code for training purposes!

resource “aws_s3_bucket” “my_data” {
  bucket = “client-private-data-2026”
  # ERROR: The bucket is public, anyone can download the files.
  acl    = “public-read” 
}

resource “aws_security_group” “allow_all” {
  name        = “allow_all_traffic”
  
  # ERROR: SSH (port 22) is open to the entire internet
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = “tcp”
    cidr_blocks = [“0.0.0.0/0”]
  }
}

resource “aws_ebs_volume” “example” {
  availability_zone = “us-east-1a”
  size              = 40
  # ERROR: Encryption is disabled
  encrypted         = false
}

Translated with DeepL.com (free version)
