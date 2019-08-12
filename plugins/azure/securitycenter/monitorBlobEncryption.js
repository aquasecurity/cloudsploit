const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Blob Encryption',
    category: 'Security Center',
    description: 'Ensures that Blob Storage Encryption monitoring is enabled.',
    more_info: 'When this setting is enabled, Security Center audits blob encryption in all storage accounts to enhance data at rest protection.',
    recommended_action: '1. Go to Azure Security Center 2. Click on Security policy 3. Click on your Subscription 4. Click on ASC Default 5. Look for the Audit missing blob encryption for storage accounts setting. 6. Ensure that it is set to AuditIfNotExists',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policies',
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
                    'Unable to query Policy Assignments: ' + helpers.addError(policyAssignments),location);
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
                helpers.addResult(results, 0, 'There is no existing ASC Default Policy Assignment.', location);
                return rcb();
            }

            if (policyAssignment.parameters &&
                policyAssignment.parameters.storageEncryptionMonitoringEffect &&
                policyAssignment.parameters.storageEncryptionMonitoringEffect.value &&
                policyAssignment.parameters.storageEncryptionMonitoringEffect.value === 'Disabled') {
                helpers.addResult(results, 2,
                    'Monitor Storage Blob Encryption is Disabled', location);
            } else {
                helpers.addResult( results, 0,
                    'Monitor Storage Blob Encryption is Enabled.',location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};