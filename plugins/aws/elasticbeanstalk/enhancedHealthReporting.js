var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Enhanced Health Reporting',
    category: 'ElasticBeanstalk',
    domain: 'Application Integration',
    description: 'Enhanced health reporting allow AWS Elastic Beanstalk to gather additional information about'
                + 'resources in your environment and aid in the identification of issues that can cause your'
                + 'application to become unavailable.',
    more_info: 'Enhanced Health Reporting is the AWS Elastic Beanstalk feature that allows the service to gather'
                + 'additional information about the resources available within your EB environments.',
    recommended_action: 'Ensure that the Enhanced Health Reporting feature is enabled for all Amazon Elastic Beanstalk (EB) environments provisioned in your AWS account.',
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

                if (environment.Health === 'Green') {
                    helpers.addResult(results, 0, `Enhanced Health Reporting feature is enabled for environment ${environment.EnvironmentName}. Environment health is ${environment.HealthStatus}`, region, resource);
                } else {
                    helpers.addResult(results, 2, `Enhanced Health Reporting feature is not enabled for environment: ${environment.EnvironmentName}`, region, resource);
                }

                ecb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
