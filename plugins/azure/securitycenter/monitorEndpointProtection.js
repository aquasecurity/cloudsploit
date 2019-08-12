const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Endpoint Protection',
    category: 'Security Center',
    description: 'Ensures Endpoint Protection monitoring is enabled in Security Center.',
    more_info: 'When this setting is enabled, Security Center audits the Endpoint Proction in all Vms to enhance data protection at rest.',
    recommended_action: '1. Go to Azure Security Center 2. Click on Security policy 3. Click on your Subscription 4. Click on ASC Default 5. Look for the Monitor missing Endpoint Protection in Azure Security Center setting. 6. Ensure that it is set to AuditIfNotExists',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {

            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);

            if (!policyAssignments) return rcb();

            if (policyAssignments.err || !policyAssignments.data) {
                helpers.addResult(results, 3,
                    'Unable to query Policy Assignments: ' + helpers.addError(policyAssignments), location);
                return rcb();
            }

            if (!policyAssignments.data.length) {
                helpers.addResult(results, 0, 'No existing Policy Assignments', location);
                return rcb();
            }

            const policyAssignment = policyAssignments.data.find((policyAssignment) => {
                return (policyAssignment.displayName &&
                    policyAssignment.displayName.includes("ASC Default")) ||
                    (policyAssignment.displayName &&
                        policyAssignment.displayName.includes("ASC default"));
            });

            if (!policyAssignment) {
                helpers.addResult(results, 0, 'There are no existing ASC Default Policy Assignments.', location);
                return rcb();
            };

            if (policyAssignment.parameters && 
                policyAssignment.parameters.endpointProtectionMonitoringEffect && 
                policyAssignment.parameters.endpointProtectionMonitoringEffect.value &&
                policyAssignment.parameters.endpointProtectionMonitoringEffect.value === 'Disabled') {
                helpers.addResult(results, 2,
                    'Monitor Endpoint Protection is Disabled', location);
            } else {
                helpers.addResult(results, 0,
                    'Monitor Endpoint Protection is Enabled.', location);
            };

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};