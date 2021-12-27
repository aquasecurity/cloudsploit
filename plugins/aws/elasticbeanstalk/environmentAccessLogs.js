var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Environment Access Logs',
    category: 'ElasticBeanstalk',
    domain: 'Application Integration',
    description: 'Ensure that your Amazon Elastic Beanstalk environment is configured to save logs for load balancer associated with the application environment.',
    more_info: 'Elastic Load Balancing provides access logs that capture detailed information about requests sent to your load balancer. Each log contains information such as the time the request was received, the client\'s IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.',
    recommended_action: 'Go to specific environment, select Configuration, edit Load Balancer category, and enable Store logs',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html',
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
                    'Unable to query for ElasticBeanstalk environments: ' + helpers.addError(describeEnvironments), region);
                return rcb();
            }

            if (!describeEnvironments.data.length) {
                helpers.addResult(results, 0,
                    'No ElasticBeanstalk environments found', region);
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
                        'Unable to query for environment configuration settings: ' + helpers.addError(describeConfigurationSettings),
                        region, resource);
                    return ecb();
                }

                if (!describeConfigurationSettings.data.ConfigurationSettings.length) {
                    helpers.addResult(results, 2, 'Environment does not have any log configuration', region, resource);
                    return ecb();
                }

                let OptionSettings = describeConfigurationSettings.data.ConfigurationSettings.map(({ OptionSettings }) => OptionSettings );
                let accesLogs = OptionSettings.flat().find(option => option.OptionName === 'AccessLogsS3Enabled' );

                if (accesLogs && accesLogs.Value === 'true') {
                    helpers.addResult(results, 0,
                        'Access Logs for environment: ' + environment.EnvironmentName + ' are enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Access Logs for environment: ' + environment.EnvironmentName + ' are not enabled',
                        region, resource);
                }

                ecb();
            }, function() {
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
