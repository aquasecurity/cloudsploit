var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Role Last Used',
    category: 'IAM',
    description: 'Ensures IAM roles that have not been used within the given time frame are deleted.',
    more_info: 'IAM roles that have not been used for a long period may contain old access policies that could allow unintended access to resources if accidentally attached to new services. These roles should be deleted.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2019/11/identify-unused-iam-roles-easily-and-remove-them-confidently-by-using-the-last-used-timestamp/',
    recommended_action: 'Delete IAM roles that have not been used within the expected time frame.',
    apis: ['IAM:listRoles', 'IAM:getRole'],
    settings: {
        iam_role_last_used_fail: {
            name: 'IAM Role Last Used Fail',
            description: 'Return a failing result when IAM roles exceed this number of days without being used',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 180
        },
        iam_role_last_used_warn: {
            name: 'IAM Role Last Used Warn',
            description: 'Return a warning result when IAM roles exceed this number of days without being used',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 90
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            iam_role_last_used_fail: settings.iam_role_last_used_fail || this.settings.iam_role_last_used_fail.default,
            iam_role_last_used_warn: settings.iam_role_last_used_warn || this.settings.iam_role_last_used_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);

        var listRoles = helpers.addSource(cache, source,
            ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM roles: ' + helpers.addError(listRoles));
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }

        async.each(listRoles.data, function(role, cb){
            if (!role.RoleName) return cb();

            // Get role details
            var getRole = helpers.addSource(cache, source,
                ['iam', 'getRole', region, role.RoleName]);

            if (!getRole || getRole.err || !getRole.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM role details: ' + role.RoleName + ': ' + helpers.addError(getRole), 'global', role.Arn);
                return cb();
            }

            if (!getRole.data.Role || !getRole.data.Role.RoleLastUsed ||
                !getRole.data.Role.RoleLastUsed.LastUsedDate) {
                helpers.addResult(results, 2,
                    'IAM role: ' + role.RoleName + ' has not been used', 'global', role.Arn);
                return cb();
            }

            var daysAgo = helpers.daysAgo(getRole.data.Role.RoleLastUsed.LastUsedDate);

            var returnCode = 0;
            var returnMsg = `IAM role was last used ${daysAgo} days ago in the ${getRole.data.Role.RoleLastUsed.Region || 'unknown'} region`;
            if (daysAgo > config.iam_role_last_used_fail) {
                returnCode = 2;
            } else if (daysAgo > config.iam_role_last_used_warn) {
                returnCode = 1;
            }

            helpers.addResult(results, returnCode, returnMsg, 'global', role.Arn, custom);

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};