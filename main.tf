provider "aws" {
  region = "eu-west-2"
}

# ✅ IAM Role for EC2 to pull from ECR
resource "aws_iam_role" "ec2_ecr_role" {
  name = "ec2-ecr-role-docker-flask-demo"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# ✅ Attach AmazonEC2ContainerRegistryReadOnly to the Role
resource "aws_iam_role_policy_attachment" "ecr_policy_attachment" {
  role       = aws_iam_role.ec2_ecr_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# ✅ Instance Profile for EC2 to assume the role
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile-docker-flask-demo"
  role = aws_iam_role.ec2_ecr_role.name
}

# ✅ Security Group to allow SSH (22) and HTTP (80)
resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Allow HTTP and SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ Reference the default VPC
data "aws_vpc" "default" {
  default = true
}

# ✅ EC2 Instance
resource "aws_instance" "web_server" {
  ami                    = "ami-0cfd0973db26b893b" # Amazon Linux 2
  instance_type          = "t2.micro"
  key_name               = "uthman-key-verified"   # 👈 Must match .pem from AWS Console
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y docker
              systemctl start docker
              usermod -a -G docker ec2-user

              # Log in to ECR and run container
              aws ecr get-login-password --region eu-west-2 | docker login --username AWS --password-stdin 162811751175.dkr.ecr.eu-west-2.amazonaws.com
              docker pull 162811751175.dkr.ecr.eu-west-2.amazonaws.com/flask-demo:latest
              docker run -d -p 80:80 162811751175.dkr.ecr.eu-west-2.amazonaws.com/flask-demo:latest
              EOF

  tags = {
    Name = "docker-flask-demo"
  }
}
