variable "vpc_id" {
  description = "id of vpc where all resources are created"
}

variable "region" {
  description = "aws region"
}

variable "ami_id" {
  type        = string
  description = "ami used to launch instances"
}

variable "app_name" {
  type        = string
  description = "name of application"
}

variable "account_arn" {
  description = "arn of account where all resources are created"
}

variable "project_tags" {
  type        = map(any)
  default     = {}
  description = "tags applied to all resources"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "public subnet ids (used for alb and autoscaling group)"
}

variable "domain_name" {
  description = "domain to be attached to alb; ssl cert will be issued"
}

variable "create_api_id" {
  type        = bool
  description = "appends random numbers to domain attached to alb; results in api_id.subdomain.com"
}

variable "cicd_hosted_zone_id" {
  type        = string
  description = "id of hosted zone where cicd project will be launched"
}

variable "instance_profile_arn" {
  type        = string
  description = "arn of instance profile associated with EC2 instances"
}



variable "instance_size" {
  type        = string
  description = "size of instance to launch"
}
variable "min_number_of_instances" {
  type        = number
  description = "minimum number of instances to scale down to"
}

variable "max_number_of_instances" {
  type        = number
  description = "max number of instances to scale down to"
}

variable "desired_number_of_instances" {
  type        = number
  description = "maximum number of in ASG must have"
}

variable "code_deploy_service_role_arn" {
  type        = string
  description = "arn of service role associated with code deploy"
}


variable "key_owner_arn" {
  type        = string
  description = "arn of account where kms key is created"
}

variable "key_owner_id" {
  type        = string
  description = "id of account where kms key is created"
}

variable "key_administrators" {
  type        = list(string)
  description = "arn of iam users allowed to perform admin (rotate/delete/etc) actions on key"
}

variable "repository" {
  type        = string
  description = "the owner and name of the repository where source changes are to be detected. Example: UserName/RepoName, OrgName/RepoName"
}

