var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticBeanstalk Managed Platform Updates',
    category: 'ElasticBeanstalk',
    description: 'Ensures ElasticBeanstalk applications are configured to managed updates.',
    more_info: 'Environment for an application should be configured to allow platform managed updates.',
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
                var describeConfigurationSettings = helpers.addSource(cache, source, ['elasticbeanstalk', 'describeConfigurationSettings', region, environment.EnvironmentName]);
                if (!describeConfigurationSettings) return ecb();

                if (describeConfigurationSettings.err ||
                    !describeConfigurationSettings.data ||
                    !describeConfigurationSettings.data.ConfigurationSettings) {
                    helpers.addResult(results, 3,
                        'Unable to query for environment configuration settings',
                        region, resource);   
                    return ecb();
                }

                if (!describeConfigurationSettings.data.ConfigurationSettings.length) {
                    helpers.addResult(results, 0, 'No environment configuration settings found', region, resource);
                    return ecb();
                }

                for (var p in describeConfigurationSettings.data.ConfigurationSettings) {
                    var param = describeConfigurationSettings.data.ConfigurationSettings[p];

                    for (var s in param.OptionSettings) {
                        var setting = param.OptionSettings[s];

                        if (setting.Namespace && setting.Namespace === 'aws:elasticbeanstalk:managedactions' &&
                            setting.OptionName && setting.OptionName === 'ManagedActionsEnabled') {
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
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
