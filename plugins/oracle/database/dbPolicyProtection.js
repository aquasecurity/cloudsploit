var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Database Policy Protection',
    category: 'Database',
    description: 'Ensures policy statements have deletion protection for database systems, databases, and database homes unless it is an administrator group.',
    more_info: 'Adding deletion protection to Oracle database policies mitigates unintended deletion of database services by unauthorized users or groups.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/dbaas_security.htm',
    recommended_action: 'Ensure policy statements have deletion protection for Database Systems, databases, and Database Homes unless it is an administrator group.',
    apis: ['policy:list'],
    settings: {
        policy_group_admins: {
            name: 'Admin groups with delete permissions.',
            description: 'The admin groups allowed to delete resources.',
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
                if (policy.statements) {
                    policy.statements.forEach(statement => {

                        const statementLower = statement.toLowerCase();

                        if (statementLower.indexOf('allow') > -1 &&
                            (statementLower.indexOf('manage') > -1 ||
                                statementLower.indexOf('use') > -1) &&
                            (statementLower.indexOf('request.permission') === -1 &&
                                statementLower.indexOf('!=') === -1 &&
                                statementLower.indexOf('_delete') === -1 &&
                                (statementLower.indexOf('db_system_') === -1 ||
                                statementLower.indexOf('database_') === -1 ||
                                statementLower.indexOf('db_home_') === -1)) &&
                            (statementLower.indexOf('db-systems') > -1 ||
                                statementLower.indexOf('databases') > -1 ||
                                statementLower.indexOf('db-homes') > -1 ||
                                statementLower.indexOf('all-resources') > -1)) {

                            policyProtection = false;
                            var statementArr = statementLower.split(' ');
                            var mySeverity = 2;

                            if (statementArr[1] === 'any-user') {
                                var groupName = statementArr[2] === 'to' ? '' : statementArr[2];
                                var compartment = statementArr[6] === 'tenancy' ? 'tenancy' : statementArr[6];
                                var compartmentName = statementArr[7] === 'tenancy' ? '' : statementArr[7];
                                var groupType = statementArr[1];
                            } else {
                                var groupName = statementArr[2] === 'to' ? '' : statementArr[2];
                                var compartment = statementArr[7] === 'tenancy' ? 'tenancy' : statementArr[7];
                                var compartmentName = statementArr[7] === 'tenancy' ? '' : statementArr[8];
                                var groupType = 'The ' + statementArr[1];
                            }

                            if (groupName === config.policy_group_admins.toLowerCase()) return;
                            if (statementArr.indexOf('request.user.name') > -1) {
                                groupType = 'The user';
                                groupName = statementArr[statementArr.length - 1];
                                mySeverity = 1;
                            }

                            helpers.addResult(results, mySeverity,
                                `${groupType} ${groupName} has the ability to delete all database services in ${compartment} ${compartmentName}`, region, policy.id);
                        }
                    });

                    if (policyProtection) {
                        helpers.addResult(results, 0, 'All policies have database delete protection enabled', region);
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