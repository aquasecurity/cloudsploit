var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Glue ETL Job Security Configuration',
    category: 'Glue',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that AWS Glue ETL jobs use a security configuration.',
    more_info: 'A Glue security configuration defines how the data written by a job is encrypted: CloudWatch Logs, job bookmarks and S3 data. A job without a security configuration writes its output, logs and bookmarks without the encryption settings the organisation requires.',
    link: 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html',
    recommended_action: 'Modify the Glue ETL job to use a security configuration (the required one, when a name is configured for this plugin).',
    apis: ['Glue:getJobs', 'STS:getCallerIdentity'],
    settings: {
        glue_etl_job_security_configuration: {
            name: 'Glue ETL Job Required Security Configuration',
            description: 'Name of the security configuration every ETL job must use. When empty, any security configuration is accepted.',
            regex: '^[A-Za-z0-9_-]*$',
            default: ''
        }
    },
    realtime_triggers: ['glue:CreateJob', 'glue:UpdateJob', 'glue:DeleteJob'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var requiredConfiguration = settings.glue_etl_job_security_configuration || this.settings.glue_etl_job_security_configuration.default;

        async.each(regions.glue, function(region, rcb) {
            var getJobs = helpers.addSource(cache, source, ['glue', 'getJobs', region]);

            if (!getJobs) return rcb();

            if (getJobs.err || !getJobs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Glue ETL jobs: ' + helpers.addError(getJobs), region);
                return rcb();
            }

            if (!getJobs.data.length) {
                helpers.addResult(results, 0, 'No Glue ETL jobs found', region);
                return rcb();
            }

            getJobs.data.forEach(function(item) {
                var resource = 'arn:' + awsOrGov + ':glue:' + region + ':' + accountId + ':job/' + item.Name;
                var configuration = item.SecurityConfiguration;

                if (!configuration) {
                    helpers.addResult(results, 2, 'Glue ETL job does not have a security configuration', region, resource);
                } else if (requiredConfiguration && configuration !== requiredConfiguration) {
                    helpers.addResult(results, 2,
                        'Glue ETL job uses security configuration "' + configuration + '" instead of "' + requiredConfiguration + '"', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Glue ETL job uses security configuration "' + configuration + '"', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
