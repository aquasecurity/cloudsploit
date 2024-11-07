const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor System Updates',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Monitor System Updates is enabled in Microsoft Defender.',
    more_info: 'When this setting is enabled, Microsoft Defender for Cloud will audit virtual machines for pending OS or system updates.',
    recommended_action: 'Ensure System Update monitoring is configured for virtual machines from the Microsoft Defender.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference',
    apis: ['policyAssignments:list'],
    compliance: {
        pci: 'PCI requires all system components have the latest updates ' +
             'and patches installed within a month of release.'
    },
    realtime_triggers: ['microsoftauthorization:policyassignments:write','microsoftauthorization:policyassignments:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {
            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'systemUpdatesMonitoringEffect',
                'Monitor System Updates', results, location);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};