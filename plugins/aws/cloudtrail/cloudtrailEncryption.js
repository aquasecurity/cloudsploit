var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Encryption',
    category: 'CloudTrail',
    description: 'Ensures CloudTrail encryption at rest is enabled for logs',
    more_info: 'CloudTrail log files contain sensitive information about an account and should be encrypted at rest for additional protection.',
    recommended_action: 'Enable CloudTrail log encryption through the CloudTrail console or API',
    link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',
    apis: ['CloudTrail:describeTrails'],
    compliance: {
        cis2: '2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudtrail, function(region, rcb){
            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CloudTrail encryption status: ' + helpers.addError(describeTrails), region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
            } else if (describeTrails.data[0]) {
                for (var t in describeTrails.data) {
                    if (describeTrails.data[t].S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) continue;
                    if (!describeTrails.data[t].KmsKeyId) {
                        helpers.addResult(results, 2, 'CloudTrail encryption is not enabled',
                            region, describeTrails.data[t].TrailARN);
                    } else {
                        helpers.addResult(results, 0, 'CloudTrail encryption is enabled',
                            region, describeTrails.data[t].TrailARN);
                    }
                }
            } else {
                helpers.addResult(results, 2, 'CloudTrail is enabled but is not properly configured', region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};