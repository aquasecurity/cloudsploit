var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Trusted Cross Account Roles',
    category: 'IAM',
    description: 'Ensures that only trusted cross-account IAM roles can be used.',
    more_info: 'IAM roles should be configured to allow access to trusted account IDs.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html',
    recommended_action: 'Delete the IAM roles that are associated with untrusted account IDs.',
    apis: ['IAM:listRoles'],
    settings: {
        whitelisted_accounts: {
            name: 'Allowed cross-account role account IDs',
            description: 'Return a failing result if cross-account role contains any account ID other than these account IDs',
            regex: '^[0-9{12}]$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var whitelisted_accounts = settings.whitelisted_accounts || this.settings.whitelisted_accounts.default;
        whitelisted_accounts = whitelisted_accounts.split(',');
        // RegExp to get account ID from 'arn:aws:iam::{account ID}:root' principal
        var accountRegExp = /(?<=arn:aws:iam::)(.*?)(?=:)/g;
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

        var awsRolesFound = false;

        listRoles.data.forEach(role => {
            if (!role.AssumeRolePolicyDocument) return;

            try {
                var assumeRolePolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
            } catch (e) {
                helpers.addResult(results, 3,
                    'IAM role policy document is not valid JSON.',
                    'global', role.Arn);
                return;
            }
            var restrictedAccounts = [];
            var crossAccountRole = false;
            
            if (assumeRolePolicy.Statement && assumeRolePolicy.Statement.length) {
                for (var s in assumeRolePolicy.Statement) {
                    var statement = assumeRolePolicy.Statement[s];
                    
                    if (statement.Principal &&
                        statement.Principal.AWS) {
                        crossAccountRole = true;
                        awsRolesFound = true;

                        var account = statement.Principal.AWS.match(accountRegExp).toString();

                        if (!whitelisted_accounts.includes(account)) restrictedAccounts.push(account);
                    }
                }

                if (crossAccountRole && !restrictedAccounts.length) {
                    helpers.addResult(results, 0,
                        'Cross-account role :' + role.RoleName + ': contains trusted account ID(s)',
                        'global', role.Arn);
                }
                else if (crossAccountRole) {
                    helpers.addResult(results, 2,
                        'Cross-account role :' + role.RoleName + ': contains these untrusted account ID(s): ' + restrictedAccounts.join(', '),
                        'global', role.Arn);
                }
            }
        });

        if (!awsRolesFound) {
            helpers.addResult(results, 0, 'No cross-account IAM roles found', 'global');
        }
        
        callback(null, results, source);
    }
};