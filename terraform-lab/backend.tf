terraform {
  backend "s3" {
    bucket = "drift-detector-tfstate-aa3f37b0"
    key    = "drift-detector/terraform.tfstate"
    region = "eu-north-1"
  }
}