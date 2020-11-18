module.exports = {
    aws: {
        bucketVersioning:{
            title: 'S3 Bucket Versioning through OPA',
            category: 'S3',
            description: 'Ensures object versioning is enabled on S3 buckets',
            path: './plugins/aws/s3/bucketversioning.rego',
            apis: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
            rules: {
                2: 'data.s3.bucketversioning.s3regionviolation',
                0: 'data.s3.bucketversioning.s3regionallowed'
            },
            messages: {
                arnTemplate: 'arn:aws:s3:::',
                region: 'global',
                2: 'Bucket : resource.Name has versioning disabled',
                0: 'Bucket : resource.Name has versioning enabled'
            }
        },
        sqsEncrypted:{
            title: 'SQS Encrypted',
            category: 'SQS',
            description: 'Ensures SQS encryption is enabled',
            path: './plugins/aws/sqs/sqsEncrypted.rego',
            apis: ['SQS:listQueues', 'SQS:getQueueAttributes'],
            rules: {
                2: 'data.sqs.encryption.sqsencdis',
                1: 'data.sqs.encryption.sqsencdefault',
                0: 'data.sqs.encryption.sqsenccmk'
            },
            messages: {
                2: 'The SQS queue does not use a KMS key for SSE',
                1: 'The SQS queue uses the default KMS key for SSE',
                0: 'The SQS queue uses a KMS key for SSE'
            }
        }
    }
};