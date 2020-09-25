var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticBeanstalk Managed Platform Updates',
    category: 'ElasticBeanstalk',
    description: 'Ensures ElasticBeanstalk applications are configured to use managed updates.',
    more_info: 'Environments for an application should be configured to allow platform managed updates.',
    link: 'https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-platform-update-managed.html',
    recommended_action: 'Update the environment to enable managed updates.',
    apis: ['ElasticBeanstalk:describeEnvironments', 'ElasticBeanstalk:describeConfigurationSettings'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        
        async.each(regions.elasticbeanstalk, function(region, rcb){
            var describeEnvironments = helpers.addSource(cache, source, ['elasticbeanstalk', 'describeEnvironments', region]);

            if (!describeEnvironments) return rcb();

            if (describeEnvironments.err || !describeEnvironments.data) {
                helpers.addResult(results, 3,
                    'Unable to query for application environments', region);
                return rcb();
            }

            if (!describeEnvironments.data.length) {
                helpers.addResult(results, 0,
                    'No application environments found', region);
                return rcb();
            }

            async.each(describeEnvironments.data, function(environment, ecb){
                var resource = environment.EnvironmentArn;
                var describeConfigurationSettings = helpers.addSource(cache, source, ['elasticbeanstalk', 'describeConfigurationSettings', region, environment.EnvironmentArn]);

                if (!describeConfigurationSettings ||
                    describeConfigurationSettings.err ||
                    !describeConfigurationSettings.data ||
                    !describeConfigurationSettings.data.ConfigurationSettings) {
                    helpers.addResult(results, 3,
                        'Unable to query for environment configuration settings',
                        region, resource);   
                    return ecb();
                }

                if (!describeConfigurationSettings.data.ConfigurationSettings.length) {
                    helpers.addResult(results, 2, 'No environment configuration settings found', region, resource);
                    return ecb();
                }

                var found = false;

                for (var p in describeConfigurationSettings.data.ConfigurationSettings) {
                    var param = describeConfigurationSettings.data.ConfigurationSettings[p];

                    if (!param.OptionSettings) continue;

                    for (var s in param.OptionSettings) {
                        var setting = param.OptionSettings[s];

                        if (setting.Namespace && setting.Namespace === 'aws:elasticbeanstalk:managedactions' &&
                            setting.OptionName && setting.OptionName === 'ManagedActionsEnabled') {
                            found = true;
                            if (setting.Value && setting.Value === 'true') {
                                helpers.addResult(results, 0,
                                    'Managed platform updates for environment: ' + environment.EnvironmentName + ' are enabled',
                                    region, resource);
                            } else {
                                helpers.addResult(results, 2,
                                    'Managed platform updates for environment: ' + environment.EnvironmentName + ' are not enabled',
                                    region, resource);
                            }
                        }
                    }
                }

                if (!found) {
                    helpers.addResult(results, 2,
                        'Managed platform updates for environment: ' + environment.EnvironmentName + ' are not enabled',
                        region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
