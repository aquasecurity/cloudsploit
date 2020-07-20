const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor SQL Auditing',
    category: 'Security Center',
    description: 'Ensures that Monitor SQL Auditing is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center will monitor SQL databases.',
    recommended_action: 'Ensure SQL auditing monitoring is configured for SQL databases from the Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function(location, rcb) {

            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'sqlAuditingMonitoringEffect',
                'Monitor SQL Auditing', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
