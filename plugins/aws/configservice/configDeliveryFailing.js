var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Config Delivery Failing',
    category: 'ConfigService',
    domain: 'Management and Governance',
    description: 'Ensure that the AWS Config log files are delivered to the S3 bucket in order to store logging data for auditing purposes without any failures.',
    more_info: 'Amazon Config keep record of the changes within the configuration of your AWS resources and it regularly stores this data to log files that are send to an S3 bucket specified by you.'+
        'Sometimes you lose the ability to audit the configuration changes made within your AWS account this happen when AWS Config is not able to deliver log files to its recipient due to delivery errors or misconfigurations , the service is unable to send the recorded information to the designated bucket.',
    recommended_action: 'Enable AWS Config log files to be delivered without any failures to designated S3 bucket, So that user could save logging data for auditing.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html',
    apis: ['ConfigService:describeConfigurationRecorderStatus'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        async.each(regions.configservice, function(region, rcb){
            var describeConfigurationRecorderStatus = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorderStatus', region]);

            if (!describeConfigurationRecorderStatus) return rcb();

            if (describeConfigurationRecorderStatus.err || !describeConfigurationRecorderStatus.data ||
                !describeConfigurationRecorderStatus.data.length) {
                helpers.addResult(results, 3,
                    'Unable to query for Config Service status: ' + helpers.addError(describeConfigurationRecorderStatus), region);
                return rcb();
            }

            for (let record of describeConfigurationRecorderStatus.data) {
                if (record.lastStatus.toUpperCase() === 'SUCCESS') {
                    helpers.addResult(results, 0,
                        'The AWS Config service succeeded in delivering the last log file to the designated recipient.',
                        region);
                } else {
                    helpers.addResult(results, 2,
                        'The AWS Config service failed to deliver the last log file to the designated recipient.',
                        region);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};