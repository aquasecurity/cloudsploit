var async = require('async');
var AWS = require('aws-sdk');

//
// Default to the AWS SDK credential lookup behavior which searches in the following order.
//
// 1. Loaded from IAM roles for Amazon EC2 (if running on EC2),
// 2. Loaded from the shared credentials file (~/.aws/credentials),
// 3. Loaded from environment variables,
// 4. Loaded from a JSON file on disk,
// 5. Hardcoded in your application
//
// see: http://docs.aws.amazon.com/AWSJavaScriptSDK/guide/node-configuring.html#Setting_AWS_Credentials
//
// The credentials can be configured manually by using one of the code blocks below.
//
var AWSConfig = AWS.config

// var AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

// var AWSConfig = require(__dirname + '/../../cloudsploit-secure/scan-test-credentials.json');

var plugins = [
    'iam/rootAccountSecurity.js',
    'iam/usersMfaEnabled.js',
    'iam/passwordPolicy.js',
    'iam/accessKeys.js',
    'iam/groupSecurity.js',
    'cloudtrail/cloudtrailEnabled.js',
    'cloudtrail/cloudtrailBucketDelete.js',
    'ec2/accountLimits.js',
    'ec2/certificateExpiry.js',
    'ec2/insecureCiphers.js',
    'vpc/detectClassic.js',
    'ec2/securityGroups.js',
    's3/s3Buckets.js',
    'route53/domainSecurity.js',
    'rds/databaseSecurity.js'
];

console.log('CATEGORY\t\tPLUGIN\t\t\t\tTEST\t\t\t\tRESOURCE\t\t\tREGION\t\tSTATUS\tMESSAGE');

async.eachSeries(plugins, function(pluginPath, callback){
    var plugin = require(__dirname + '/plugins/' + pluginPath);

    plugin.run(AWSConfig, function(err, result){
        //console.log(JSON.stringify(result, null, 2));
        for (i in result.tests) {
            for (j in result.tests[i].results) {
                var statusWord;
                if (result.tests[i].results[j].status === 0) {
                    statusWord = 'OK';
                } else if (result.tests[i].results[j].status === 1) {
                    statusWord = 'WARN';
                } else if (result.tests[i].results[j].status === 2) {
                    statusWord = 'FAIL';
                } else {
                    statusWord = 'UNKNOWN';
                }
                console.log(result.category + '\t\t' + result.title + '\t' + result.tests[i].title + '\t' + (result.tests[i].results[j].resource || 'N/A') + '\t' + (result.tests[i].results[j].region || 'Global') + '\t\t' + statusWord + '\t' + result.tests[i].results[j].message);
            }
        }
        callback(err);
    });
}, function(err, data){
    if (err) return console.log(err);
});
