resource "aws_s3_bucket" "data" {
  bucket = "example-insecure-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "open-to-the-world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  publicly_accessible = true
  storage_encrypted   = false
  username            = "admin"
  password            = "not-a-real-password"
}
