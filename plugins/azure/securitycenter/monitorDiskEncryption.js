const async = require('async');

const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Disk Encryption',
    category: 'Security Center',
    description: 'Ensures Disk Encryption monitoring is enabled in Security Center.',
    more_info: 'When this setting is enabled, Security Center audits disk encryption in all virtual machines (Windows and Linux as well) to enhance data at rest protection.',
    recommended_action: '1. Go to Azure Security Center 2. Click on Security policy 3. Click on your Subscription 4. Click on ASC Default 5. Look for the Disk encryption should be applied on virtual machines setting. 6. Ensure that it is set to AuditIfNotExists',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list','disks:list'],
    compliance: {
        hipaa: 'HIPAA requires data to be encrypted at rest. Enabling disk encryption ' +
                'monitoring ensures this configuration is not modified undetected.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function (location, rcb) {

            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            var disksList = helpers.addSource(cache, source, ['disks', 'list', location]);

            if(disksList &&
                disksList.data &&
                disksList.data.length>0) {

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
                    policyAssignment.parameters.diskEncryptionMonitoringEffect &&
                    policyAssignment.parameters.diskEncryptionMonitoringEffect.value &&
                    policyAssignment.parameters.diskEncryptionMonitoringEffect.value === 'Disabled') {
                    helpers.addResult(results, 2,
                        'Disk Encryption Protection is Disabled', location);
                } else {
                    helpers.addResult(results, 0,
                        'Disk Encryption Protection is Enabled.', location);
                };
            } else {
                helpers.addResult(results, 0,
                    'No matching resources found, ignoring monitoring requirement', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};