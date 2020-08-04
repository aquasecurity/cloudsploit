const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Endpoint Protection',
    category: 'Security Center',
    description: 'Ensures Endpoint Protection monitoring is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center audits the Endpoint Protection setting for all virtual machines for malware protection.',
    recommended_action: 'Enable Adaptive Application Controls for Endpoint Protection from the Azure Security Center by ensuring AuditIfNotExists setting is used to monitor missing Endpoint Protection.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {

            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'endpointProtectionMonitoringEffect',
                'Monitor Endpoint Protection', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};