const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Blob Encryption',
    category: 'Security Center',
    description: 'Ensures that Blob Storage Encryption monitoring is enabled',
    more_info: 'When this setting is enabled, Security Center audits blob encryption in all storage accounts to enhance data at rest protection.',
    recommended_action: 'Enable Adaptive Application Controls for Storage Accounts from the Azure Security Center by ensuring AuditIfNotExists setting is used for blob encryption.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policies',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {

            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'storageEncryptionMonitoringEffect',
                'Monitor Storage Blob Encryption', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};