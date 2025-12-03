var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Security Hub Enabled',
    category: 'SecurityHub',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that AWS Security Hub is enabled.',
    more_info: 'AWS Security Hub provides a comprehensive view of your security posture across your AWS accounts. It aggregates, organises, and prioritises security findings from various AWS services.',
    link: 'https://aws.amazon.com/security-hub/',
    recommended_action: 'Enable AWS Security Hub for enhanced security monitoring and compliance.',
    apis: ['SecurityHub:describeHub'],
    realtime_triggers: ['securityhub:EnableSecurityHub', 'securityhub:DisableSecurityHub'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.securityhub, function(region, rcb) {
            var describeHub = helpers.addSource(cache, source, ['securityhub', 'describeHub', region]);

            if (!describeHub) return rcb();

            if (describeHub.err && describeHub.err.name === 'InvalidAccessException'){
                helpers.addResult(results, 2, 'Security Hub is not enabled', region);
            } else if (describeHub.err || !describeHub.data) {
                helpers.addResult(results, 3, `Unable to query for Security Hub: ${helpers.addError(describeHub)}`, region);
            } else {
                helpers.addResult(results, 0, 'Security Hub is enabled', region,describeHub.data.HubArn);
            }

            return rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
