const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Whitelisting Enabled',
    category: 'Security Center',
    description: 'Ensure that Security Center Monitor Adaptive Application Whitelisting is enabled.',
    more_info: 'Adaptive application controls work in conjunction with machine learning to analyze processes running in a VM and helps control which applications can run in the VM. This helps harden those VMs against malware.',
    recommended_action: '1. Go to Azure Security Center 2. Click on Security policy 3. Click on your Subscription Name 4. Look for the "Monitor application whitelisting" setting. 5. Ensure that it is not set to Disabled',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptiveapplication',
    apis: ['policyAssignments:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function (location, rcb) {
            const policyAssignments = helpers.addSource(
                cache, source, ['policyAssignments', 'list', location]
            );

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
                return policyAssignment.displayName.includes("ASC Default")
                    || policyAssignment.displayName.includes("ASC default")
            });

            if (!policyAssignment) {
                helpers.addResult(results, 0,
                    'There are no ASC Default Policy Assignments.', location);
                return rcb();
            }

            if (policyAssignment.parameters &&
                policyAssignment.parameters.adaptiveApplicationControlsMonitoringEffect &&
                policyAssignment.parameters.adaptiveApplicationControlsMonitoringEffect.value == 'Disabled') {

                helpers.addResult(results, 2,
                    'Monitor Adaptive Application Whitelisting is disabled', location);

            } else {

                helpers.addResult(results, 0,
                    'Monitor Adaptive Application Whitelisting is enabled', location);

            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
