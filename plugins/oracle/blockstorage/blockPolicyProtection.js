var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Block Storage Policy Protection',
    category: 'Block Storage',
    description: 'Ensure policy statements have deletion protection for block volumes unless it is an administrator group.',
    more_info: 'Adding deletion protection to Oracle block volume policies mitigates unintended deletion of block and boot volumes by unauthorized users or groups.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/iam_security.htm',
    recommended_action: 'When writing policies, avoid blanket statements, and add a where statement with the line request.permission != {VOLUME_DELETE, VOLUME_BACKUP_DELETE, VOLUME_ATTACHMENT_DELETE}.',
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
            var entered = false;

            policies.data.forEach(policy => {
                if (policy.statements &&
                    policy.statements.length) {
                    entered = true;
                    policy.statements.forEach(statement => {

                        const statementLower = statement.toLowerCase();

                        if (statementLower.indexOf('allow') > -1 &&
                            (statementLower.indexOf('manage') > -1 ||
                                statementLower.indexOf('use') > -1) &&
                            (statementLower.indexOf('request.permission') === -1 &&
                                statementLower.indexOf('!=') === -1 &&
                                statementLower.indexOf('_delete') === -1 &&
                                (statementLower.indexOf('volume_') === -1 ||
                                    statementLower.indexOf('volume_backup_') === -1 ||
                                    statementLower.indexOf('volume_attachments_') === -1)) &&
                                (statementLower.indexOf('volume') > -1 ||
                                    statementLower.indexOf('volumes-backups')  > -1 ||
                                    statementLower.indexOf('volume-attachments') > -1 ||
                                    statementLower.indexOf('volume-family') > -1 ||
                                    statementLower.indexOf('all-resources') > -1)) {

                            policyProtection = false;
                            var statementArr = statementLower.split(' ');
                            var statementNormalArr = statement.split(' ');

                            var severity = 2;

                            if (statementArr[1] === 'any-user'  || statementArr[1] === 'dynamic-group') {
                                var groupName = statementArr[2] === 'to' ? '' : statementNormalArr[2];
                                var compartment = statementArr[6] === 'tenancy' ? 'tenancy' : statementArr[6];
                                var compartmentName = (!statementArr[7] || statementArr[7] === 'tenancy') ? '' : statementNormalArr[7];
                                var groupType = statementArr[1];
                            } else {
                                var groupName = statementArr[2] === 'to' ? '' : statementNormalArr[2];
                                var compartment = statementArr[7] === 'tenancy' ? 'tenancy' : statementArr[7];
                                var compartmentName = (!statementArr[7] || statementArr[7] === 'tenancy') ? '' : statementNormalArr[8];
                                var groupType = 'The ' + statementArr[1];
                            }

                            if (groupName === config.policy_group_admins.toLowerCase()) return;
                            if (statementArr.indexOf('request.user.name') > -1) {
                                groupType = 'The user';
                                groupName = statementArr[statementArr.length - 1];
                                severity = 1;
                            }

                            helpers.addResult(results, severity,
                                `${groupType} ${groupName} has the ability to delete all block storage volumes in ${compartment} ${compartmentName}`, region, policy.id);
                        }
                    });


                }
            });

            if (policyProtection && entered) {
                helpers.addResult(results, 0, 'All policies have block volume delete protection enabled', region);
            }
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};