var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Config Delivery Failing',
    category: 'ConfigService',
    domain: 'Management and Governance',
    description: 'Ensure that the AWS Config log files are delivered to the S3 bucket in order to store logging data for auditing purposes without any failures.',
    more_info: 'Amazon Config keep record of the changes within the configuration of your AWS resources and it regularly stores this data to log files that are send to an S3 bucket specified by you.',
    recommended_action: 'Configure AWS Config log files to be delivered without any failures to designated S3 bucket.',
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

            if (describeConfigurationRecorderStatus.err || !describeConfigurationRecorderStatus.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Config Service configuration recorder statuses: ' + helpers.addError(describeConfigurationRecorderStatus), region);
                return rcb();
            }

            if (!describeConfigurationRecorderStatus.data.length) {
                helpers.addResult(results, 0,
                    'No Config Service configuration recorder statuses found', region);
                return rcb();
            }

            if (describeConfigurationRecorderStatus.data[0].lastStatus &&
                describeConfigurationRecorderStatus.data[0].lastStatus.toUpperCase() === 'SUCCESS') {
                helpers.addResult(results, 0,
                    'AWS Config service is delivering log files to the designated recipient successfully',
                    region);
            } else {
                helpers.addResult(results, 2,
                    'AWS Config service is not delivering log files to the designated recipient successfully',
                    region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};