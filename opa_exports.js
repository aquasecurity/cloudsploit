module.exports = {
    aws: {
        bucketVersioning:{
            title: 'S3 Bucket Versioning through OPA',
            description: 'Ensures object versioning is enabled on S3 buckets',
            path: './plugins/aws/s3/bucketversioning.rego',
            apis: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
            rules: {
                denied: 'data.s3.bucketversioning.s3regionviolation',
                allowed: 'data.s3.bucketversioning.s3regionallowed'
            },
            messages: {
                arnTemplate: 'arn:aws:s3:::',
                failed: 'Bucket : resource.Name has versioning disabled',
                passed: 'Bucket : resource.Name has versioning enabled'
            }
        }
    }
};