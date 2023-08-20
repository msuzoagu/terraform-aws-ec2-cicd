/**
 * # Introduction
 * 
 * Creates a simple 2 stage blue-green CI/CD pipeline for 
 * AWS EC2 compute platform. 
 * 
 * The Pipeline created consists of 2 stages: 
 * - Source: Github 
 * - Deploy: CodeDeploy 
 * 
*/


/* S3 Bucket used to store application load balancer (alb) logs */
resource "aws_s3_bucket" "alb_log" {
  bucket = lower(join("-", [local.alb_name, "logs"]))

  force_destroy = true

  tags = merge(
    var.project_tags,
    {
      service = "s3",
      app     = var.project_tags.prefix
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_s3_bucket_policy" "alb_log" {
  bucket = aws_s3_bucket.alb_log.id
  policy = data.aws_iam_policy_document.alb_log.json
}

data "aws_iam_policy_document" "alb_log" {
  policy_id = "s3_bucket_lb_logs"

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = [aws_s3_bucket.alb_log.arn, "${aws_s3_bucket.alb_log.arn}/*"]

    principals {
      identifiers = [var.account_arn]
      type        = "AWS"
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_log.arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [local.albLogBucketPrincipal]
    }
  }
}


/* Application Load Balancer */
##############################
# => add subnets so ALB is 
# => available in each public
# => az in deployment region
##############################
resource "aws_security_group" "alb" {
  name        = local.alb_sg_name
  vpc_id      = var.vpc_id
  description = "Allow HTTP(S) inbound traffic to ALB"

  # To allow health checks 
  # SG needs to allow all
  # outbound requests
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Inbound HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Inbound HTTP from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.project_tags,
    {
      Name = local.alb_sg_name
    }
  )
}

resource "aws_alb" "this" {
  name               = local.alb_name
  internal           = "false"
  subnets            = var.public_subnet_ids
  load_balancer_type = "application"

  security_groups = [
    aws_security_group.alb.id
  ]

  access_logs {
    bucket  = aws_s3_bucket.alb_log.bucket
    enabled = true
  }

  depends_on = [
    aws_security_group.alb
  ]

  tags = merge(
    var.project_tags,
    {
      Name = local.alb_name
    }
  )
}

/* AWS Target Group */
##############################
# => tells load balancer 
# => where to direct traffic
##############################
resource "aws_lb_target_group" "this" {
  health_check {
    path                = "/"
    timeout             = 5
    matcher             = 200
    interval            = 10
    protocol            = "HTTP"
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }

  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = var.vpc_id
  name        = "${local.albTargetGroupName}-albTgtGroup"

  depends_on = [
    aws_alb.this
  ]

  tags = merge(
    var.project_tags,
    {
      Name = "${local.albTargetGroupName}-albTgtGroup"
    }
  )
}


/*      SSL Cert for Domain name      */
resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

##########################################
# => update the hosted zone 
# => with CNAME record of
# => issued acm certificate
##########################################
resource "aws_route53_record" "cname" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  ttl             = 60
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  zone_id         = var.cicd_hosted_zone_id
  allow_overwrite = true
}


####################################################
# => checks hosted zone for a cname entry
# => pointing to certificate issued; if
# => entry is present, validation worked
####################################################
resource "aws_acm_certificate_validation" "this" {
  certificate_arn = aws_acm_certificate.this.arn

  validation_record_fqdns = [
    for record in aws_route53_record.cname : record.fqdn
  ]
}


##########################################
# => alias is created in hosted zone so 
# => that traffic for ${var.domain_name} 
# => is sent to load balancer
##########################################
resource "aws_route53_record" "alias" {
  zone_id = var.cicd_hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    # Target of Route53 alias
    name    = aws_alb.this.dns_name
    zone_id = aws_alb.this.zone_id

    # evaluate_target_health  = true
    evaluate_target_health = false
  }

  depends_on = [
    aws_alb.this
  ]
}


/* AWS LOAD BALANCER LISTENERS */
resource "aws_alb_listener" "http" {
  port              = 80
  protocol          = "HTTP"
  load_balancer_arn = aws_alb.this.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_alb_listener" "https" {
  port              = 443
  protocol          = "HTTPS"
  load_balancer_arn = aws_alb.this.arn
  ssl_policy        = "ELBSecurityPolicy-2015-05"
  certificate_arn   = aws_acm_certificate.this.arn

  default_action {
    target_group_arn = aws_lb_target_group.this.arn
    type             = "forward"
  }
}


##################################################
# => All traffic with Host Header var.domain_name
# => will be redirected to target group that
# => autoscaling servers are attached to
##################################################
resource "aws_alb_listener_rule" "this" {
  listener_arn = aws_alb_listener.http.arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  condition {
    host_header {
      values = [var.domain_name]
    }
  }
}


/* AWS LAUNCH CONFIGURATION */
############################################################
## this cannot be updated after creation via Amazon Web
## Service API. To update, Terraform will destroy the
## existing resources and create a replacement. In order
## to effectively use a Launch Configuration resource
## with an AutoScaling Group resource, it is recommended
## to specify create_before_destroy in a lifecyle block.
## Either omit Launch Configuration name attribute or 
## specify partial name via name_prefix
############################################################
resource "aws_security_group" "webservers" {
  name        = local.webserver_sg_name
  vpc_id      = var.vpc_id
  description = "Allow HTTP(S) inbound from ${local.alb_sg_name}"

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    description     = "Allow HTTP from ${local.alb_sg_name}"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    description     = "Allow HTTPS from ${local.alb_sg_name}"
    security_groups = [aws_security_group.alb.id]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = local.webserver_sg_name
  }
}

resource "aws_launch_template" "this" {
  name          = var.app_name
  image_id      = var.ami_id
  instance_type = var.instance_size

  iam_instance_profile {
    arn = var.instance_profile_arn
  }

  instance_initiated_shutdown_behavior = "terminate"

  network_interfaces {
    delete_on_termination       = true
    associate_public_ip_address = false
    security_groups             = [aws_security_group.webservers.id]
  }

  tag_specifications {
    resource_type = "instance"

    tags = var.project_tags
  }

  # lifecycle – special instruction, which is declaring 
  # how new launch configuration rules applied during 
  # update. We are using create_before_destroy here to 
  # create new instances from a new launch configuration 
  # before destroying the old ones. This option commonly 
  # used during rolling deployments 
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.project_tags,
    {
      service = "launch_template"
    }
  )
}


/* AWS Auto Scaling Group */
resource "aws_autoscaling_group" "this" {
  name             = join("-", [var.app_name, "asg"])
  min_size         = var.min_number_of_instances
  max_size         = var.max_number_of_instances
  desired_capacity = var.desired_number_of_instances

  force_delete = true
  # health_check_type     = "ELB"

  launch_template {
    id      = aws_launch_template.this.id
    version = aws_launch_template.this.latest_version
  }


  target_group_arns = [aws_lb_target_group.this.arn]



  depends_on = [
    aws_alb.this
  ]

  metrics_granularity = "1Minute"
  vpc_zone_identifier = var.public_subnet_ids

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]

  # Required to redeploy without an outage.
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [load_balancers, target_group_arns]
  }

  dynamic "tag" {
    for_each = var.project_tags
    content {
      key                 = tag.value
      propagate_at_launch = true
      value               = tag.value
    }
  }
}

resource "aws_autoscaling_attachment" "this" {
  lb_target_group_arn    = aws_lb_target_group.this.arn
  autoscaling_group_name = aws_autoscaling_group.this.id
}

resource "aws_autoscaling_policy" "this" {
  autoscaling_group_name = aws_autoscaling_group.this.name
  name                   = join("-", [var.app_name, "asg", "policy"])
  scaling_adjustment     = 1
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
}


/* Codedeploy App */
resource "aws_codedeploy_app" "this" {
  compute_platform = "Server"
  name             = var.app_name

  tags = var.project_tags
}

resource "aws_codedeploy_deployment_group" "this" {
  app_name         = aws_codedeploy_app.this.name
  service_role_arn = var.code_deploy_service_role_arn

  autoscaling_groups = [aws_autoscaling_group.this.name]

  deployment_group_name = join(
    "-",
    [var.project_tags.env, var.app_name]
  )

  deployment_config_name = "CodeDeployDefault.OneAtATime"

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  load_balancer_info {
    elb_info {
      name = aws_alb.this.name
    }
  }

  ### Newly added to test blue-green deployments
  blue_green_deployment_config {
    deployment_ready_option {
      # action_on_timeout    = "STOP_DEPLOYMENT"
      # wait_time_in_minutes = 60
      action_on_timeout = "CONTINUE_DEPLOYMENT"
    }

    green_fleet_provisioning_option {
      action = "COPY_AUTO_SCALING_GROUP"
    }

    terminate_blue_instances_on_deployment_success {
      action = "KEEP_ALIVE"
    }
  }
}

/* CodeStar Connection */
resource "aws_codestarconnections_connection" "this" {
  name          = join("-", [var.app_name, "codestar", "github"])
  provider_type = "GitHub"
}

/* CodePipeline Service Role */
data "aws_iam_policy_document" "codepipeline_trust_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codepipeline_service_role" {
  path = "/"
  name = local.codepipelineServiceRole

  assume_role_policy = data.aws_iam_policy_document.codepipeline_trust_policy.json
}

data "aws_iam_policy_document" "codepipeline_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["*"]
    condition {
      test     = "StringEqualsIfExists"
      variable = "iam:PassedToService"

      values = [
        "ec2.amazonaws.com"
      ]
    }
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "codedeploy:GetDeployment",
      "codedeploy:GetApplication",
      "codedeploy:CreateDeployment",
      "codedeploy:GetDeploymentConfig",
      "codedeploy:GetApplicationRevision",
      "codedeploy:RegisterApplicationRevision"
    ]
  }
  statement {
    effect    = "Allow"
    resources = [aws_codestarconnections_connection.this.arn]
    actions   = ["codestar-connections:UseConnection"]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ec2:*",
      #"s3:*",
      "sns:*",
      "rds:*",
      "sqs:*",
      "cloudwatch:*",
      "autoscaling:*",
      "elasticloadbalancing:*"
    ]
  }
  statement {
    effect = "Allow"
    resources = [
      aws_s3_bucket.codepipeline.arn,
      "${aws_s3_bucket.codepipeline.arn}/*"
    ]
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketVersioning",
      "s3:PutObject"
      #"s3:PutObjectAcl",
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "opsworks:UpdateApp",
      "opsworks:UpdateStack",
      "opsworks:DescribeApps",
      "opsworks:DescribeStacks",
      "opsworks:DescribeCommands",
      "opsworks:CreateDeployment",
      "opsworks:DescribeDeployments",
      "opsworks:DescribeInstances"
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "states:StartExecution",
      "states:DescribeExecution",
      "states:DescribeStateMachine"
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "appconfig:GetDeployment",
      "appconfig:StopDeployment",
      "appconfig:StartDeployment"
    ]
  }
}

resource "aws_iam_policy" "codepipeline_permissions" {
  name        = join("-", [var.app_name, "CodePipelinePermissions"])
  description = "permissions for ${local.codepipelineServiceRole}"

  policy = data.aws_iam_policy_document.codepipeline_permissions.json
}

resource "aws_iam_role_policy_attachment" "codepipeline_permissions" {
  role       = aws_iam_role.codepipeline_service_role.name
  policy_arn = aws_iam_policy.codepipeline_permissions.arn
}


/* CodePipeline KMS KEY */
resource "aws_kms_key" "codepipeline" {
  description              = "for ${aws_s3_bucket.codepipeline.bucket}"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  policy = data.aws_iam_policy_document.codepipeline_kms_key.json


  tags = merge(
    var.project_tags
  )

  depends_on = [aws_iam_role.codepipeline_service_role]
}

data "aws_iam_policy_document" "codepipeline_kms_key" {
  statement {
    sid = "Grant Full Access"

    effect  = "Allow"
    actions = ["kms:*"]

    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.key_owner_arn]
    }
  }

  statement {
    sid = "Grant Key Administration Access"

    effect = "Allow"
    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = var.key_administrators
    }
  }

  statement {
    sid = "Grant key use to S3"

    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:DescribeKey",
      "kms:GenerateDataKey*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [var.key_owner_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid    = "Grant key use to service role"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:DescribeKey",
      "kms:GenerateDataKey*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.codepipeline_service_role.arn]
    }
  }
}

/* CodePipeline Bucket */
resource "aws_s3_bucket" "codepipeline" {
  bucket        = lower(join("-", [var.app_name, "code-artifact"]))
  force_destroy = true

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "codepipeline" {
  bucket = aws_s3_bucket.codepipeline.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "codepipeline" {
  bucket = aws_s3_bucket.codepipeline.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.codepipeline.arn
      sse_algorithm     = "aws:kms"
    }
  }

  depends_on = [aws_kms_key.codepipeline]
}

##-------------------------------------------------------------
## CodePipeline does not support resource-based policies but it
## is best practice to attache the following policy to the s3
## artifact bucket created: https://docs.aws.amazon.com/codepipeline/
##latest/userguide/security_iam_resource-based-policy-examples.html
##-------------------------------------------------------------
data "aws_iam_policy_document" "codepipeline_bucket" {
  statement {
    sid       = "DenyUnEncryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.codepipeline.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"

      values = [
        "aws:kms"
      ]
    }
  }

  statement {
    sid       = "DenyInsecureConnections"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.codepipeline.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"

      values = [
        false
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "codepipeline" {
  bucket = aws_s3_bucket.codepipeline.id
  policy = data.aws_iam_policy_document.codepipeline_bucket.json
}


/* CodePipeline */
resource "aws_codepipeline" "this" {
  name     = join("-", [var.app_name, "codepipeline"])
  role_arn = aws_iam_role.codepipeline_service_role.arn

  artifact_store {
    type     = "S3"
    location = aws_s3_bucket.codepipeline.bucket

    encryption_key {
      id   = aws_kms_key.codepipeline.arn
      type = "KMS"
    }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      region           = var.region
      namespace        = "source_variables"
      run_order        = "1"
      output_artifacts = ["SourceArtifact"]

      configuration = {
        BranchName           = var.project_tags.env
        ConnectionArn        = aws_codestarconnections_connection.this.arn
        FullRepositoryId     = var.repository
        OutputArtifactFormat = "CODE_ZIP"
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeploy"
      version         = "1"
      region          = var.region
      namespace       = "DeployVariables"
      run_order       = "1"
      input_artifacts = ["SourceArtifact"]

      configuration = {
        ApplicationName     = "${var.app_name}"
        DeploymentGroupName = aws_codedeploy_app.this.name
      }
    }
  }
}
