# Intentionally vulnerable sample: Terraform cloud misconfigurations.
# Scanner test input only.

resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-exports"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "db" {
  name        = "prod-db"
  description = "Production database access"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "primary" {
  identifier          = "prod-primary"
  engine              = "postgres"
  instance_class      = "db.t3.large"
  username            = "postgres"
  password            = "Passw0rd!2024"
  storage_encrypted   = false
  publicly_accessible = true
  skip_final_snapshot = true
}
