const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Total Number of Subscription Owners',
    category: 'Security Center',
    description: 'Ensures that Total Number of Subscription Owners is being Monitored in Security Center',
    more_info: 'Total Number of Subscription Owners should be monitored to meet you organization\'s security compliance requirements.',
    recommended_action: 'Enable Monitor for Total Number of Subscription Owners by ensuring AuditIfNotExists setting is used for \'A maximum of 3 owners should be designated for your subscription\' from the Azure Security Center.',
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
                'identityDesignateLessThanOwnersMonitoringEffect',
                'Monitor for Total Number of Subscription Owners', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};