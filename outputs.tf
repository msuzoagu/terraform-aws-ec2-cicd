output "alb_log_bucket_id" {
  value = aws_s3_bucket.alb_log.id
}

output "alb_log_bucket_arn" {
  value = aws_s3_bucket.alb_log.arn
}

output "acm_cert_all" {
  value = aws_acm_certificate.this
}

output "acm_cert_arn" {
  value = aws_acm_certificate.this.arn
}

output "acm_cert_domain_name" {
  value = aws_acm_certificate.this.domain_name
}
