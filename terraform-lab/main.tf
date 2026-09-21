terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  required_version = ">= 1.6.0"
}

provider "aws" {
  region = "eu-north-1"
}

resource "aws_s3_bucket" "app" {
  bucket = "drift-detector-app-aa3f37b0"

  tags = {
    Name          = "drift-detector-app"
    Environment   = "dev"
    ManagedBy     = "Terraform"
    TerraformName = "app"
  }
}


resource "aws_instance" "web" {
  ami           = "ami-06ce3f5aa5b3e591c"
  instance_type = "t3.micro"

  tags = {
    Name          = "drift-detector-web"
    Environment   = "dev"
    ManagedBy     = "Terraform"
    TerraformName = "web"
  }
}