var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Config Global Resources',
    category: 'ConfigService',
    domain: 'Management and Governance',
    description: 'Ensure that AWS Config service include Global resources in order to have complete visibility over the configuration changes made within your AWS account.',
    more_info: 'The AWS Config Service Including Global resources into your AWS Config settings will allow you to keep track of IAM resources such as IAM users, groups, roles and managed policies.',
    recommended_action: 'AWS Config service to configure Global resources in order to have complete visibility over the configuration changes made within your AWS account. .',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html',
    apis: ['ConfigService:describeConfigurationRecorders'],
  
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        async.each(regions.configservice, function(region, rcb){
            var describeConfigurationRecorders = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorders', region]);
            
            if (!describeConfigurationRecorders) return rcb();

            if (describeConfigurationRecorders.err || !describeConfigurationRecorders.data ||
                !describeConfigurationRecorders.data.length) {
                helpers.addResult(results, 3,
                    'Unable to query for Config Service: ' + helpers.addError(describeConfigurationRecorders), region);
                return rcb();
            }
           
            for (let record of describeConfigurationRecorders.data) {
                if (!record.roleARN) continue;

                let resource = record.roleARN;

                if (record.recordingGroup &&
                    record.recordingGroup.includeGlobalResourceTypes == true) {
                    helpers.addResult(results, 0,
                        'The configuration changes made to your AWS Global resources are currently recorded.',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'The configuration changes made to your AWS Global resources are not currently recorded.',
                        region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
