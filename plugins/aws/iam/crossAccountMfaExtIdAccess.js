var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cross-Account Access External ID and MFA',
    category: 'IAM',
    description: 'Ensures that either MFA or external IDs are used to access AWS roles.',
    more_info: 'IAM roles should be configured to require either a shared external ID or use an MFA device when assuming the role.',
    link: 'https://aws.amazon.com/blogs/aws/mfa-protection-for-cross-account-access/',
    recommended_action: 'Update the IAM role to either require MFA or use an external ID.',
    apis: ['IAM:listRoles'],

    run: function(cache, settings, callback) {
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

        var found = false;

        listRoles.data.forEach(role => {
            if (!role.AssumeRolePolicyDocument) {
                return;
            }

            var assumeRolePolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
            
            if (assumeRolePolicy.Statement &&
                assumeRolePolicy.Statement.length &&
                assumeRolePolicy.Statement[0].Principal &&
                assumeRolePolicy.Statement[0].Principal.AWS) {
                found = true;
                if (assumeRolePolicy.Statement[0].Condition &&
                            (assumeRolePolicy.Statement[0].Condition.Bool &&
                                assumeRolePolicy.Statement[0].Condition.Bool['aws:MultiFactorAuthPresent'] &&
                                assumeRolePolicy.Statement[0].Condition.Bool['aws:MultiFactorAuthPresent'] === 'true') ||
                            (assumeRolePolicy.Statement[0].Condition.StringEquals &&
                                assumeRolePolicy.Statement[0].Condition.StringEquals['sts:ExternalId'])) {
                    helpers.addResult(results, 0,
                        'Cross-account role :' + role.RoleName + ': requires MFA/external ID',
                        'global', role.Arn);
                } else {
                    helpers.addResult(results, 2,
                        'Cross-account role :' + role.RoleName + ': does not require MFA/external ID',
                        'global', role.Arn);
                }
            }
        });

        if (!found) {
            helpers.addResult(results, 0, 'No cross-account IAM roles found');
        }
        
        callback(null, results, source);
    }
};