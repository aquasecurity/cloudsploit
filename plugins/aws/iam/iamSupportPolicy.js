var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Support Policy',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that an IAM role, group or user exists with specific permissions to access support center.',
    more_info: 'AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. An IAM Role should be present to allow authorized users to manage incidents with AWS Support.',
    link: 'https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html',
    recommended_action: 'Ensure that an IAM role has permission to access support center.',
    apis: ['IAM:listRoles', 'IAM:listAttachedRolePolicies'],
    realtime_triggers: ['iam:CreateRole','iam:DeleteRole','iam:AttachRolePolicy','iam:DetachRolePolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);
        var supportPolicyArn = `arn:${helpers.defaultPartition(settings)}:iam::aws:policy/AWSSupportAccess`;

        var listRoles = helpers.addSource(cache, source, ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM roles: ' + helpers.addError(listRoles));
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0,
                'No IAM policies found');
            return callback(null, results, source);
        }

        var supportRoleArn = null;

        for (var role of listRoles.data) {
            if (!role.RoleName || supportRoleArn) continue;

            var listAttachedRolePolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedRolePolicies', region, role.RoleName]);

            if (!listAttachedRolePolicies || listAttachedRolePolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for role: ' + role.RoleName + ': ' +
                    helpers.addError(listAttachedRolePolicies), 'global', role.Arn);
                continue;
            }

            if (listAttachedRolePolicies.data &&
                listAttachedRolePolicies.data.AttachedPolicies) {
                for (var policy of listAttachedRolePolicies.data.AttachedPolicies) {
                    if (policy.PolicyArn === supportPolicyArn) {
                        supportRoleArn = role.Arn;
                        break;
                    }
                }
            }
        }

        if (supportRoleArn) {
            helpers.addResult(results, 0,
                'AWSSupportAccess policy is attached to a user, role or group', 'global', supportRoleArn);
        } else if (!results.length) {
            helpers.addResult(results, 2,
                'No role, user or group attached to the AWSSupportAccess policy', 'global');
        }

        callback(null, results, source);
    }
};
