// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    cloudfront: {
        listDistributions: 'ARN',
        getDistribution: 'Distribution.ARN'
    },
    s3: {
        listBuckets: 'name',
    },
    sns:{
        listTopics: 'describeKey',
        getTopicAttributes: 'Attributes.TopicArn'
    },
    kms:{
        describeKey: 'KeyMetadata.Arn'
    },
    iam:{
        generateCredentialReport: 'arn',
        listServerCertificates: 'Arn',
        getGroup: 'Arn',
        getRole: 'Role.Arn'
    }
};