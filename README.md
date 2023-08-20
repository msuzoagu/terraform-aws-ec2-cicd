<!-- BEGIN_TF_DOCS -->
# Introduction

Creates a simple 2 stage blue-green CI/CD pipeline for
AWS EC2 compute platform.

The Pipeline created consists of 2 stages:
- Source: Github
- Deploy: CodeDeploy

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.5.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.7.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 5.7.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_acm_certificate.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate) | resource |
| [aws_acm_certificate_validation.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate_validation) | resource |
| [aws_alb.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb) | resource |
| [aws_alb_listener.http](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb_listener) | resource |
| [aws_alb_listener.https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb_listener) | resource |
| [aws_alb_listener_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/alb_listener_rule) | resource |
| [aws_autoscaling_attachment.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_attachment) | resource |
| [aws_autoscaling_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group) | resource |
| [aws_autoscaling_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_policy) | resource |
| [aws_codedeploy_app.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codedeploy_app) | resource |
| [aws_codedeploy_deployment_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codedeploy_deployment_group) | resource |
| [aws_codepipeline.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codepipeline) | resource |
| [aws_codestarconnections_connection.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codestarconnections_connection) | resource |
| [aws_iam_policy.codepipeline_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.codepipeline_service_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.codepipeline_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_key.codepipeline](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_launch_template.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template) | resource |
| [aws_lb_target_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_route53_record.alias](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route53_record.cname](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_s3_bucket.alb_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.codepipeline](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_policy.alb_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_policy.codepipeline](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.codepipeline](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.codepipeline](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_security_group.alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.webservers](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_iam_policy_document.alb_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.codepipeline_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.codepipeline_kms_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.codepipeline_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.codepipeline_trust_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_arn"></a> [account\_arn](#input\_account\_arn) | arn of account where all resources are created | `any` | n/a | yes |
| <a name="input_ami_id"></a> [ami\_id](#input\_ami\_id) | ami used to launch instances | `string` | n/a | yes |
| <a name="input_app_name"></a> [app\_name](#input\_app\_name) | name of application | `string` | n/a | yes |
| <a name="input_cicd_hosted_zone_id"></a> [cicd\_hosted\_zone\_id](#input\_cicd\_hosted\_zone\_id) | id of hosted zone where cicd project will be launched | `string` | n/a | yes |
| <a name="input_code_deploy_service_role_arn"></a> [code\_deploy\_service\_role\_arn](#input\_code\_deploy\_service\_role\_arn) | arn of service role associated with code deploy | `string` | n/a | yes |
| <a name="input_create_api_id"></a> [create\_api\_id](#input\_create\_api\_id) | appends random numbers to domain attached to alb; results in api\_id.subdomain.com | `bool` | n/a | yes |
| <a name="input_desired_number_of_instances"></a> [desired\_number\_of\_instances](#input\_desired\_number\_of\_instances) | maximum number of in ASG must have | `number` | n/a | yes |
| <a name="input_domain_name"></a> [domain\_name](#input\_domain\_name) | domain to be attached to alb; ssl cert will be issued | `any` | n/a | yes |
| <a name="input_instance_profile_arn"></a> [instance\_profile\_arn](#input\_instance\_profile\_arn) | arn of instance profile associated with EC2 instances | `string` | n/a | yes |
| <a name="input_instance_size"></a> [instance\_size](#input\_instance\_size) | size of instance to launch | `string` | n/a | yes |
| <a name="input_key_administrators"></a> [key\_administrators](#input\_key\_administrators) | arn of iam users allowed to perform admin (rotate/delete/etc) actions on key | `list(string)` | n/a | yes |
| <a name="input_key_owner_arn"></a> [key\_owner\_arn](#input\_key\_owner\_arn) | arn of account where kms key is created | `string` | n/a | yes |
| <a name="input_key_owner_id"></a> [key\_owner\_id](#input\_key\_owner\_id) | id of account where kms key is created | `string` | n/a | yes |
| <a name="input_max_number_of_instances"></a> [max\_number\_of\_instances](#input\_max\_number\_of\_instances) | max number of instances to scale down to | `number` | n/a | yes |
| <a name="input_min_number_of_instances"></a> [min\_number\_of\_instances](#input\_min\_number\_of\_instances) | minimum number of instances to scale down to | `number` | n/a | yes |
| <a name="input_project_tags"></a> [project\_tags](#input\_project\_tags) | tags applied to all resources | `map(any)` | `{}` | no |
| <a name="input_public_subnet_ids"></a> [public\_subnet\_ids](#input\_public\_subnet\_ids) | public subnet ids (used for alb and autoscaling group) | `list(string)` | n/a | yes |
| <a name="input_region"></a> [region](#input\_region) | aws region | `any` | n/a | yes |
| <a name="input_repository"></a> [repository](#input\_repository) | the owner and name of the repository where source changes are to be detected. Example: UserName/RepoName, OrgName/RepoName | `string` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | id of vpc where all resources are created | `any` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_acm_cert_all"></a> [acm\_cert\_all](#output\_acm\_cert\_all) | n/a |
| <a name="output_acm_cert_arn"></a> [acm\_cert\_arn](#output\_acm\_cert\_arn) | n/a |
| <a name="output_acm_cert_domain_name"></a> [acm\_cert\_domain\_name](#output\_acm\_cert\_domain\_name) | n/a |
| <a name="output_alb_log_bucket_arn"></a> [alb\_log\_bucket\_arn](#output\_alb\_log\_bucket\_arn) | n/a |
| <a name="output_alb_log_bucket_id"></a> [alb\_log\_bucket\_id](#output\_alb\_log\_bucket\_id) | n/a |
<!-- END_TF_DOCS -->