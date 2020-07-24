const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor SQL Encryption',
    category: 'Security Center',
    description: 'Ensures that Monitor SQL Encryption is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center will monitor for unencrypted SQL databases, associated backups, and transaction log files.',
    recommended_action: 'Ensure SQL encryption monitoring is configured for SQL databases from the Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],
    compliance: {
        hipaa: 'HIPAA requires data to be encrypted at rest. Enabling SQL encryption ' +
                'monitoring ensures this configuration is not modified undetected.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function(location, rcb) {

            const policyAssignments = helpers.addSource(cache, source,
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'sqlEncryptionMonitoringEffect',
                'Monitor SQL Encryption', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};