var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Glue Dev Endpoint Security Configuration',
    category: 'Glue',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that AWS Glue development endpoints use a security configuration.',
    more_info: 'A Glue security configuration defines how the data handled by a development endpoint is encrypted: CloudWatch Logs, job bookmarks and S3 data. An endpoint without a security configuration does not apply the encryption settings the organisation requires.',
    link: 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html',
    recommended_action: 'Modify the Glue development endpoint to use a security configuration (the required one, when a name is configured for this plugin).',
    apis: ['Glue:getDevEndpoints', 'STS:getCallerIdentity'],
    settings: {
        glue_dev_endpoint_security_configuration: {
            name: 'Glue Dev Endpoint Required Security Configuration',
            description: 'Name of the security configuration every development endpoint must use. When empty, any security configuration is accepted.',
            regex: '^[A-Za-z0-9_-]*$',
            default: ''
        }
    },
    realtime_triggers: ['glue:CreateDevEndpoint', 'glue:UpdateDevEndpoint', 'glue:DeleteDevEndpoint'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var requiredConfiguration = settings.glue_dev_endpoint_security_configuration || this.settings.glue_dev_endpoint_security_configuration.default;

        async.each(regions.glue, function(region, rcb) {
            var getDevEndpoints = helpers.addSource(cache, source, ['glue', 'getDevEndpoints', region]);

            if (!getDevEndpoints) return rcb();

            if (getDevEndpoints.err || !getDevEndpoints.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Glue development endpoints: ' + helpers.addError(getDevEndpoints), region);
                return rcb();
            }

            if (!getDevEndpoints.data.length) {
                helpers.addResult(results, 0, 'No Glue development endpoints found', region);
                return rcb();
            }

            getDevEndpoints.data.forEach(function(item) {
                var resource = 'arn:' + awsOrGov + ':glue:' + region + ':' + accountId + ':devEndpoint/' + item.EndpointName;
                var configuration = item.SecurityConfiguration;

                if (!configuration) {
                    helpers.addResult(results, 2, 'Glue development endpoint does not have a security configuration', region, resource);
                } else if (requiredConfiguration && configuration !== requiredConfiguration) {
                    helpers.addResult(results, 2,
                        'Glue development endpoint uses security configuration "' + configuration + '" instead of "' + requiredConfiguration + '"', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Glue development endpoint uses security configuration "' + configuration + '"', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
