locals {
  prefix = join(
    "-",
    [var.project_tags.env, var.project_tags.prefix]
  )

  alb_name = join(
    "-",
    [title(var.project_tags.prefix), "ALB"]
  )

  alb_sg_name = join(
    "-",
    [title(var.project_tags.prefix), "ALB", "SG"]
  )

  webserver_name = join(
    "-",
    [title(var.project_tags.prefix), "WebServer"]
  )

  webserver_sg_name = join(
    "-",
    [title(var.project_tags.prefix), "WebServer", "SG"]
  )

  codepipelineServiceRole = join(
    "-",
    [var.app_name, "CodePipelineServiceRole"]
  )

  elbRegionAcctId = {
    "us-east-1" = "127311923021"
    "us-east-2" = "033677994240"
    "us-west-1" = "027434742980"
    "us-west-2" = "797873946194"
  }

  elbAcctId = lookup(local.elbRegionAcctId, var.region, "")

  albLogBucketPrincipal = "arn:aws:iam::${local.elbAcctId}:root"

  env = {
    "development" = "dev"
    "staging"     = "stg"
    "production"  = "prd"
  }

  shortenEnv = lookup(local.env, var.project_tags.env, "")

  albTargetGroupName = join(
    "-",
    [local.shortenEnv, var.project_tags.prefix]
  )



  # api_id_domain = "${random_id.domain_id.hex}.${var.domain_name}"
  # domain_name   = var.create_api_id ? local.api_id_domain : var.domain_name
}
