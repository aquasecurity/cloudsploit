module.exports = {
    title: 'Privilege Analysis',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Info',
    description: 'Ensures no Lambda function available in your AWS account is overly-permissive.',
    more_info: 'AWS Lambda Function should have most-restrictive IAM permissions for Lambda security best practices.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html',
    recommended_action: 'Modify IAM role attached with Lambda function to provide the minimal amount of access required to perform its tasks',
    apis: [''],
    realtime_triggers: ['lambda:CreateFunction','lambda:UpdateFunctionConfiguration', 'lambda:DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);

    }
};
