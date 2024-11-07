const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Endpoint Protection',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures Endpoint Protection monitoring is enabled in Microsoft Defender.',
    more_info: 'When this setting is enabled, Microsoft Defender for Cloud audits the Endpoint Protection setting for all virtual machines for malware protection.',
    recommended_action: 'Enable Adaptive Application Controls for Endpoint Protection from the Microsoft Defender by ensuring AuditIfNotExists setting is used to monitor missing Endpoint Protection.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference',
    apis: ['policyAssignments:list'],
    realtime_triggers: ['microsoftauthorization:policyassignments:write','microsoftauthorization:policyassignments:delete'],

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