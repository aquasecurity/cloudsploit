const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor JIT Network Access',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures Just In Time Network Access monitoring is enabled in Microsoft Defender.',
    more_info: 'When this setting is enabled, Microsoft Defender for Cloud audits Just In Time Network Access on all virtual machines (Windows and Linux as well) to enhance data protection at rest',
    recommended_action: 'Ensure JIT Network Access monitoring is configured for compute and apps from Microsoft Defender.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference',
    apis: ['policyAssignments:list'],
    realtime_triggers: ['microsoftauthorization:policyassignments:write','microsoftauthorization:policyassignments:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, (location, rcb) => {
            const policyAssignments = helpers.addSource(cache, source, 
                ['policyAssignments', 'list', location]);

            helpers.checkPolicyAssignment(policyAssignments,
                'jitNetworkAccessMonitoringEffect',
                'Monitor JIT Network Access', results, location);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
