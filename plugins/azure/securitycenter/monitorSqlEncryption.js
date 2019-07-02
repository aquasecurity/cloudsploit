const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor SQL Encryption',
    category: 'Security Center',
    description: 'Ensure that Monitor SQL Encryption is enabled in Security Center.',
    more_info: 'When this setting is Disabled, Security Center will ignore unencrypted SQL databases, associated backups, and transaction log files.',
    recommended_action: '1. Go to Azure Security Center 2. Click on Security policy 3. Click on your Subscription Name 4. Look for the "Monitor SQL encryption" setting. 5. Ensure that it is not set to Disabled',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],
    compliance: {
        hipaa: 'HIPAA requires data to be encrypted at rest. Enabling SQL encryption ' +
                'monitoring ensures this configuration is not modified undetected.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function (location, rcb) {

            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            if (!policyAssignments) return rcb();

            if (policyAssignments.err || !policyAssignments.data) {
                helpers.addResult(results, 3,
                    'Unable to query PolicyAssignments: ' + helpers.addError(policyAssignments), location);
                return rcb();
            }

            if (!policyAssignments.data.length) {
                helpers.addResult(results, 0, 'No existing Policy Assignments', location);
                return rcb();
            }

            const policyAssignment = policyAssignments.data.find((policyAssignment) => {
                return policyAssignment.displayName.includes("ASC Default")
                    || policyAssignment.displayName.includes("ASC default")
            });

            if (!policyAssignment) {
                helpers.addResult(results, 0,
                    'There are no ASC Default Policy Assignments.', location);
                return rcb();
            }

            if (policyAssignment.parameters && policyAssignment.parameters.sqlEncryptionMonitoringEffect
                && policyAssignment.parameters.sqlEncryptionMonitoringEffect.value === 'Disabled') {

                helpers.addResult(results, 2,
                    'Monitor SQL Encryption is Disabled', location);
            } else {
                helpers.addResult(results, 0,
                    'Monitor SQL Encryption is Enabled.', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};