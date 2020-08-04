const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor System Updates',
    category: 'Security Center',
    description: 'Ensures that Monitor System Updates is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center will audit virtual machines for pending OS or system updates.',
    recommended_action: 'Ensure System Update monitoring is configured for virtual machines from the Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],
    compliance: {
        pci: 'PCI requires all system components have the latest updates ' +
             'and patches installed within a month of release.'
    },

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