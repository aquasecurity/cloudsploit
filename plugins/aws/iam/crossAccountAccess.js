var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cross Account Access',
    category: 'IAM',
    description: 'Ensures that either MFA or external IDs are used to access AWS resources.',
    more_info: 'MFA/external ID adds an extra layer of security on top of roles, temporary security credentials and facilitates external third-party accounts to access your AWS resources in a secure way.',
    link: 'https://aws.amazon.com/blogs/aws/mfa-protection-for-cross-account-access/',
    recommended_action: 'Edit IAM role to require MFA or external ID.',
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

        listRoles.data.forEach(role => {
            if (!role.AssumeRolePolicyDocument) {
                return;
            }

            var assumeRolePolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
            
            if (assumeRolePolicy.Statement &&
                assumeRolePolicy.Statement.length &&
                assumeRolePolicy.Statement[0].Principal &&
                assumeRolePolicy.Statement[0].Principal.AWS) {
                if (assumeRolePolicy.Statement[0].Condition &&
                        (assumeRolePolicy.Statement[0].Condition.Bool &&
                            assumeRolePolicy.Statement[0].Condition.Bool['aws:MultiFactorAuthPresent'] &&
                            assumeRolePolicy.Statement[0].Condition.Bool['aws:MultiFactorAuthPresent'] === 'true') ||
                        (assumeRolePolicy.Statement[0].Condition.StringEquals &&
                            assumeRolePolicy.Statement[0].Condition.StringEquals['sts:ExternalId'])) {
                    helpers.addResult(results, 0,
                        'MFA/external ID is required for role :' + role.RoleName + ' :',
                        'global', role.Arn);
                } else {
                    helpers.addResult(results, 2,
                        'MFA/external ID is not required for role :' + role.RoleName + ' :',
                        'global', role.Arn);
                }
            }
        });
        
        callback(null, results, source);
    }
};