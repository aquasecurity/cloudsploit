const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor NSG Enabled',
    category: 'Security Center',
    description: 'Ensures Network Security Groups monitoring is enabled in Security Center',
    more_info: 'When this setting is enabled, Security Center will audit the Network Security Groups that are enabled on the VM for permissive rules.',
    recommended_action: 'Ensure Network Security Group monitoring is configured from the Azure Security Center.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policy-definitions',
    apis: ['policyAssignments:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {
            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'networkSecurityGroupsMonitoringEffect',
                'Monitor Network Security Groups', results, location);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};