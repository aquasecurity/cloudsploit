var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudShell Full Access Restricted',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'High',
    description: 'Ensures that the AWSCloudShellFullAccess policy is not attached to any IAM user, group, or role.',
    more_info: 'The AWSCloudShellFullAccess policy grants full access to CloudShell, including file transfer capabilities that could be used for data exfiltration. Access to this policy should be restricted or replaced with a more limited policy.',
    link: 'https://docs.aws.amazon.com/cloudshell/latest/userguide/sec-auth-with-identities.html',
    recommended_action: 'Detach the AWSCloudShellFullAccess policy from all IAM users, groups, and roles, and replace with a more restrictive policy if CloudShell access is required.',
    apis: ['IAM:listUsers', 'IAM:listAttachedUserPolicies',
        'IAM:listGroups', 'IAM:listAttachedGroupPolicies',
        'IAM:listRoles', 'IAM:listAttachedRolePolicies'],
    realtime_triggers: ['iam:AttachUserPolicy','iam:DetachUserPolicy',
        'iam:AttachGroupPolicy','iam:DetachGroupPolicy',
        'iam:AttachRolePolicy','iam:DetachRolePolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var cloudShellPolicyArn = `arn:${awsOrGov}:iam::aws:policy/AWSCloudShellFullAccess`;

        function isPolicyAttached(attachedPolicies) {
            return attachedPolicies && attachedPolicies.some(p => p.PolicyArn === cloudShellPolicyArn);
        }

        // Check users
        var listUsers = helpers.addSource(cache, source, ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM users: ' + helpers.addError(listUsers));
            return callback(null, results, source);
        }

        for (var user of listUsers.data) {
            if (!user.UserName) continue;

            var listAttachedUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedUserPolicies', region, user.UserName]);

            if (!listAttachedUserPolicies || listAttachedUserPolicies.err) continue;

            if (isPolicyAttached(listAttachedUserPolicies.data && listAttachedUserPolicies.data.AttachedPolicies)) {
                helpers.addResult(results, 2,
                    'AWSCloudShellFullAccess policy is attached to user: ' + user.UserName,
                    'global', user.Arn);
            }
        }

        // Check groups
        var listGroups = helpers.addSource(cache, source, ['iam', 'listGroups', region]);

        if (listGroups && !listGroups.err && listGroups.data) {
            for (var group of listGroups.data) {
                if (!group.GroupName) continue;

                var listAttachedGroupPolicies = helpers.addSource(cache, source,
                    ['iam', 'listAttachedGroupPolicies', region, group.GroupName]);

                if (!listAttachedGroupPolicies || listAttachedGroupPolicies.err) continue;

                if (isPolicyAttached(listAttachedGroupPolicies.data && listAttachedGroupPolicies.data.AttachedPolicies)) {
                    helpers.addResult(results, 2,
                        'AWSCloudShellFullAccess policy is attached to group: ' + group.GroupName,
                        'global', group.Arn);
                }
            }
        }

        // Check roles
        var listRoles = helpers.addSource(cache, source, ['iam', 'listRoles', region]);

        if (listRoles && !listRoles.err && listRoles.data) {
            for (var role of listRoles.data) {
                if (!role.RoleName) continue;

                var listAttachedRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listAttachedRolePolicies', region, role.RoleName]);

                if (!listAttachedRolePolicies || listAttachedRolePolicies.err) continue;

                if (isPolicyAttached(listAttachedRolePolicies.data && listAttachedRolePolicies.data.AttachedPolicies)) {
                    helpers.addResult(results, 2,
                        'AWSCloudShellFullAccess policy is attached to role: ' + role.RoleName,
                        'global', role.Arn);
                }
            }
        }

        if (!results.length) {
            helpers.addResult(results, 0,
                'AWSCloudShellFullAccess policy is not attached to any user, group, or role', 'global');
        }

        callback(null, results, source);
    }
};
