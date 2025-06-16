provider "aws" {
  region = "eu-west-2"
}

# ✅ IAM Role for EC2 to pull from ECR
resource "aws_iam_role" "ec2_ecr_role" {
  name = "ec2-ecr-role-v6"

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

# ✅ Attach CloudWatch Logs policy to the Role
resource "aws_iam_role_policy_attachment" "cloudwatch_logs" {
  role       = aws_iam_role.ec2_ecr_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# ✅ Instance Profile for EC2 to assume the role
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile-v6"
  role = aws_iam_role.ec2_ecr_role.name
}

# ✅ Security Group to allow SSH (22) and HTTP (80)
resource "aws_security_group" "web_sg" {
  name        = "web-sg-v6"
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
  key_name               = "uthman-key-verified"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
            #!/bin/bash
            dnf update -y
            dnf install -y docker
            systemctl enable docker
            systemctl start docker
            usermod -aG docker ec2-user

            yum install -y amazon-cloudwatch-agent

            docker login -u AWS -p $(aws ecr get-login-password --region eu-west-2) 162811751175.dkr.ecr.eu-west-2.amazonaws.com
            docker pull 162811751175.dkr.ecr.eu-west-2.amazonaws.com/flask-demo:latest
            docker run -d --name flask-demo -p 80:80 162811751175.dkr.ecr.eu-west-2.amazonaws.com/flask-demo:latest

            mkdir -p /opt/aws/amazon-cloudwatch-agent/etc/
            cat <<EOT > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
            {
              "logs": {
                "logs_collected": {
                  "files": {
                    "collect_list": [
                      {
                        "file_path": "/var/lib/docker/containers/*/*.log",
                        "log_group_name": "flask-demo-logs",
                        "log_stream_name": "{instance_id}"
                      }
                    ]
                  }
                }
              }
            }
            EOT

            /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
              -a fetch-config -m ec2 \
              -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
              -s
            EOF


  tags = {
    Name = "docker-flask-demo"
  }
}
# Attach CloudWatch Logs policy to the Role
resource "aws_iam_policy_attachment" "cloudwatch_logs" {
  name       = "attach-cloudwatch-logs"
  roles      = [aws_iam_role.ec2_ecr_role.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}