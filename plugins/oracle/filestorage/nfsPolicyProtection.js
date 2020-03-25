var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'File Storage Policy Protection',
    category: 'File Storage',
    description: 'Ensures policy statements have deletion protection for file storage services unless it is an administrator group.',
    more_info: 'Adding deletion protection to Oracle file storage policies mitigates unintended deletion of file storage services by unauthorized users or groups.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/filestorage_security.htm',
    recommended_action: 'When writing policies, avoid blanket statements, and add a where statement with the line request.permission != {FILE_SYSTEM_DELETE, MOUNT_TARGET_DELETE, EXPORT_SET_DELETE} .',
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
                if (policy.statements &&
                    policy.statements.length) {
                    policy.statements.forEach(statement => {

                        const statementLower = statement.toLowerCase();

                        if (statementLower.indexOf('allow') > -1 &&
                            (statementLower.indexOf('manage') > -1 ||
                                statementLower.indexOf('use') > -1) &&
                            (statementLower.indexOf('request.permission') === -1 &&
                                statementLower.indexOf('!=') === -1 &&
                                statementLower.indexOf('_delete') === -1 &&
                                (statementLower.indexOf('file_system_') === -1 ||
                                    statementLower.indexOf('mount_target_') === -1 ||
                                    statementLower.indexOf('export_set_') === -1)) &&
                            (statementLower.indexOf('file-systems') > -1 ||
                                statementLower.indexOf('mount-targets') > -1 ||
                                statementLower.indexOf('export-sets') > -1 ||
                                statementLower.indexOf('all-resources') > -1)) {

                            policyProtection = false;
                            var statementArr = statementLower.split(' ');
                            var severity = 2;

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
                                severity = 1;
                            }

                            helpers.addResult(results, severity,
                                `${groupType} ${groupName} has the ability to delete all file storage services in ${compartment} ${compartmentName}`, region, policy.id);
                        }
                    });

                    if (policyProtection) {
                        helpers.addResult(results, 0, 'All policies have file storage delete protection enabled', region);
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