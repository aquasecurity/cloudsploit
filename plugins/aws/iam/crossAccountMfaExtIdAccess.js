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

        var crossAccountfound = false;

        listRoles.data.forEach(role => {
            if (!role.AssumeRolePolicyDocument || !role.Arn) {
                return;
            }
            
            var resource = role.Arn;

            try {
                var assumeRolePolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
            } catch (e) {
                helpers.addResult(results, 3,
                    'IAM role policy document is not valid JSON.',
                    region, resource);
                return;
            }

            var goodStatements = [];
            var nonConfiguredAccounts = [];
            var crossAccountRole = false;
            
            if (assumeRolePolicy.Statement && assumeRolePolicy.Statement.length) {
                for (var s in assumeRolePolicy.Statement) {
                    var statement = assumeRolePolicy.Statement[s];
                    
                    if (statement.Principal &&
                        statement.Principal.AWS) {
                        crossAccountRole = true;
                        crossAccountfound = true;

                        if (statement.Condition &&
                            ((statement.Condition.Bool &&
                                    statement.Condition.Bool['aws:MultiFactorAuthPresent'] &&
                                    statement.Condition.Bool['aws:MultiFactorAuthPresent'] === 'true') ||
                                (statement.Condition.StringEquals &&
                                    statement.Condition.StringEquals['sts:ExternalId']))) {
                            goodStatements.push(statement);
                        } else {
                            nonConfiguredAccounts.push(statement.Principal.AWS);
                        }
                    }
                }

                if (crossAccountRole && goodStatements.length === assumeRolePolicy.Statement.length) {
                    helpers.addResult(results, 0,
                        'Cross-account role :' + role.RoleName + ': requires MFA/external ID for all accounts',
                        'global', role.Arn);
                } else if (crossAccountRole) {
                    helpers.addResult(results, 2,
                        'Cross-account role :' + role.RoleName + ': does not require MFA/external ID for these account ARNs: ' + nonConfiguredAccounts.join(', '),
                        'global', role.Arn);
                }
            }
        });

        if (!crossAccountfound) {
            helpers.addResult(results, 0, 'No cross-account IAM roles found');
        }
        
        callback(null, results, source);
    }
};