var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Environment Persistent Logs',
    category: 'ElasticBeanstalk',
    domain: 'Application Integration',
    description: 'Ensure that AWS Elastic Beanstalk environment logs are retained and saved on S3.',
    more_info: 'Elastic Beanstalk environment logs should be retained in order to keep the logging data for future audits, historical purposes or to track and analyze the EB application environment behavior for a long period of time.',
    recommended_action: 'Go to specific environment, select Configuration, edit Software category, and enable Log streaming',
    link: 'https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.cloudwatchlogs.html',
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
                let persistentLogs = OptionSettings.flat().filter(option => option.OptionName === 'LogPublicationControl' || option.OptionName === 'StreamLogs');

                if (!persistentLogs || !persistentLogs.length) {
                    helpers.addResult(results, 2,
                        'Environment Persistent Logs for environment: ' + environment.EnvironmentName + ' are not enabled',
                        region, resource);
                } else if (persistentLogs[0] && persistentLogs[0].Value === 'false' && persistentLogs[1] && persistentLogs[1].Value === 'false') {
                    helpers.addResult(results, 2,
                        'Environment Persistent Logs for environment: ' + environment.EnvironmentName + ' are not enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Environment Persistent Logs for environment: ' + environment.EnvironmentName + ' are enabled',
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
