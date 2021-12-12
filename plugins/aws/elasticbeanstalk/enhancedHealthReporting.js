var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Enhanced Health Reporting',
    category: 'ElasticBeanstalk',
    domain: 'Application Integration',
    description: 'Ensure that Amazon Elastic Beanstalk (EB) environments have enhanced health reporting feature enabled.',
    more_info: 'Enhanced health reporting is a feature that you can enable on your environment to allow AWS Elastic Beanstalk to gather additional'
        + 'information about resources in your environment. Elastic Beanstalk analyzes the information gathered to provide a better picture of overall'
        + 'environment health and aid in the identification of issues that can cause your application to become unavailable.',
    recommended_action: 'Modify Elastic Beanstalk environmentsand enable enhanced health reporting.',
    link: 'https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html',
    apis: ['ElasticBeanstalk:describeEnvironments'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);

        async.each(regions.elasticbeanstalk, function(region, rcb){
            var describeEnvironments = helpers.addSource(cache, source, ['elasticbeanstalk', 'describeEnvironments', region]);

            if (!describeEnvironments) return rcb();

            if (describeEnvironments.err || !describeEnvironments.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Elastic Beanstalk environments', region);
                return rcb();
            }

            if (!describeEnvironments.data.length) {
                helpers.addResult(results, 0,
                    'No Elastic Beanstalk environments found', region);
                return rcb();
            }

            for (let environment of describeEnvironments.data) {
                var resource = environment.EnvironmentArn;

                if (environment.Health && environment.HealthStatus) {
                    helpers.addResult(results, 0, `Enhanced Health Reporting feature is enabled for environment ${environment.EnvironmentName}.`, region, resource);
                } else {
                    helpers.addResult(results, 2, `Enhanced Health Reporting feature is not enabled for environment: ${environment.EnvironmentName}`, region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
