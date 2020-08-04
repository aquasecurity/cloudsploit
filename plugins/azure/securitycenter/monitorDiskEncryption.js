const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Disk Encryption',
    category: 'Security Center',
    description: 'Ensures Disk Encryption monitoring is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center audits disk encryption in all virtual machines to enhance data at rest protection.',
    recommended_action: 'Enable Adaptive Application Controls for Disk Encryption from the Azure Security Center by ensuring AuditIfNotExists setting is used for virtual machines.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],
    compliance: {
        hipaa: 'HIPAA requires data to be encrypted at rest. Enabling disk encryption ' +
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
                'diskEncryptionMonitoringEffect',
                'Monitor Disk Encryption', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};