var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Config Service Enabled',
    category: 'ConfigService',
    domain: 'Management and Governance',
    description: 'Ensure that Amazon Config service is pointing an S3 bucket that is active in your account in order to save configuration information',
    more_info: 'Amazon Config tracks changes within the configuration of your AWS resources and it regularly sends updated configuration details to an S3 bucket that you specify. '+
        'When AWS Config is not referencing an active S3 bucket, the service is unable to send the recorded information to the designated bucket, therefore you lose the ability to audit later the configuration changes made within your AWS account.',
    recommended_action: 'Enable that Amazon Config service is referencing an active S3 bucket in order to save configuration information.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html',
    apis: ['ConfigService:describeDeliveryChannels', 'S3:headBucket'],
  
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.configservice, function(region, rcb) {
            var describeDeliveryChannels = helpers.addSource(cache, source,
                ['configservice', 'describeDeliveryChannels', region]);

            if (!describeDeliveryChannels) return rcb();

            if (describeDeliveryChannels.err || !describeDeliveryChannels.data) {
                helpers.addResult(results, 3,
                    'Unable to query Config delivery channels: ' + helpers.addError(describeDeliveryChannels), region);
                return rcb();
            }

            if (!describeDeliveryChannels.data.length) {
                helpers.addResult(results, 0, 'No Config delivery channels found', region);
                return rcb();
            }

            let deletedBucket = [];
            for (let record of describeDeliveryChannels.data) {
                if (!record.s3BucketName) continue;

                var headBucket = helpers.addSource(cache, source,
                    ['s3', 'headBucket', region, record.s3BucketName]);

                if (headBucket && headBucket.err && headBucket.err.code &&
                    headBucket.err.code.toLowerCase() == 'notfound'){
                    deletedBucket.push(record);
                } else if (!headBucket || headBucket.err) {
                    helpers.addResult(results, 3,
                        'Unable to query S3 headbucket: ' + helpers.addError(headBucket), region);
                    continue;
                }
            }

            if (deletedBucket.length) {
                helpers.addResult(results, 2,
                    `Config Service have these buckets  ${deletedBucket.join(', ')}, not available in your account`,
                    region);

            } else {
                helpers.addResult(results, 0,
                    'Config Service have buckets available in your account', 
                    region);
            } 

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};