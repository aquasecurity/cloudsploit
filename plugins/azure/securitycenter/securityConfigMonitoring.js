const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Configuration Monitoring',
    category: 'Security Center',
    description: 'Ensures that Security Configuration Monitoring is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center will monitor virtual machines for security configurations.',
    recommended_action: 'Ensure Security Configuration Monitoring is configured for virtual machines from the Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/overview',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function(location, rcb) {

            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'systemConfigurationsMonitoringEffect',
                'Monitor Security Configuration', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
