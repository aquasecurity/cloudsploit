var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Policy Least Privilege',
    category: 'Identity',
    description: 'Ensure only service-level admins have blanket statements to manage or use resources without restriction.',
    more_info: 'Adding service-level admins to Oracle policies instead of blanket statements mitigates unintended access to resources by unauthorized users or groups.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/iam_security.htm',
    recommended_action: 'When writing policies, avoid blanket statements, and instead give full permissions only to Service-level admins, all other groups should have least access to services.',
    apis: ['policy:list'],
    compliance: {
        hipaa: 'MFA helps provide additional assurance that the user accessing ' +
            'the cloud environment has been identified. HIPAA requires ' +
            'strong controls around entity authentication which can be ' +
            'enhanced through the use of MFA.',
        pci: 'PCI requires MFA for all access to cardholder environments. ' +
            'Create an MFA key for user accounts.'
    },
    settings: {
        policy_group_admins: {
            name: 'Service-level Admins.',
            description: 'Comma separated list of all service-level admins to ignore for this plugin.',
            regex: '(?im)^([a-z_](?:\\.\\-\\w|\\-\\.\\w|\\-\\w|\\.\\w|\\w)+)$',
            default: 'Administrators'
        },
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var config = {
            policy_group_admins: settings.policy_group_admins || this.settings.policy_group_admins.default

        };

        async.each(regions.default, function (region, rcb) {
            var policies = helpers.addSource(cache, source,
                ['policy', 'list', region]);

            if (!policies) return rcb();

            if (policies.err || !policies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for policies: ' + helpers.addError(policies), region);
                return rcb();
            }

            if (!policies.data.length) {
                helpers.addResult(results, 0, 'No policies found', region);
                return rcb();
            }
            var policyProtection = true;

            policies.data.forEach(policy => {
                if (policy.statements &&
                    policy.statements.length) {
                    policy.statements.forEach(statement => {

                        const statementLower = statement.toLowerCase();

                        if (statementLower.indexOf('allow') > -1 &&
                            (statementLower.indexOf('manage') > -1 ||
                                statementLower.indexOf('use') > -1) &&
                            ((statementLower.indexOf('request.permission') === -1 &&
                                statementLower.indexOf('!=') === -1) ||
                                (statementLower.indexOf('request.operation') === -1 &&
                                    statementLower.indexOf('!=') === -1))) {

                            policyProtection = false;
                            var statementArr = statementLower.split(' ');
                            var severity = 2;

                            if (statementArr[1] === 'any-user') {
                                var groupName = statementArr[2] === 'to' ? '' : statementArr[2];
                                var resourceType = statementArr[4];
                                var compartment = statementArr[6] === 'tenancy' ? 'tenancy' : statementArr[6];
                                var compartmentName = statementArr[7] === 'tenancy' ? '' : statementArr[7];
                                var groupType = statementArr[1];
                                var verb = statementArr[3];
                            } else {
                                var groupName = statementArr[2] === 'to' ? '' : statementArr[2];
                                var resourceType = statementArr[5];
                                var compartment = statementArr[7] === 'tenancy' ? 'tenancy' : statementArr[7];
                                var compartmentName = statementArr[7] === 'tenancy' ? '' : statementArr[8];
                                var groupType = statementArr[1];
                                var verb = statementArr[4];
                            }

                            var adminsArr = config.policy_group_admins.toLowerCase().replace(' ', '').split(',');

                            if (adminsArr.indexOf(groupName) > -1) return;
                            if (statementArr.indexOf('request.user.name') > -1) {
                                groupType = 'User';
                                groupName = statementArr[statementArr.length - 1];
                                severity = 1;
                            }
                            helpers.addResult(results, severity,
                                `${groupType} ${groupName} has the ability to ${verb} ${resourceType} in ${compartment} ${compartmentName}`, region, policy.id);
                        }
                    });

                    if (policyProtection) {
                        helpers.addResult(results, 0, 'All policies follow least access.', region);
                    }
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
