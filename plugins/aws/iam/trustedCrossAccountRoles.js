var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Trusted Cross Account Roles',
    category: 'IAM',
    description: 'Ensures that only trusted cross-account IAM roles can be used.',
    more_info: 'IAM roles should be configured to allow access to trusted account IDs.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html',
    recommended_action: 'Delete the IAM roles that are associated with untrusted account IDs.',
    apis: ['IAM:listRoles', 'STS:getCallerIdentity'],
    settings: {
        whitelisted_aws_account_principals: {
            name: 'Whitelisted AWS Account Principals',
            description: 'Return a failing result if cross-account role contains any AWS account principal other than these principals',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var whitelisted_aws_account_principals = settings.whitelisted_aws_account_principals || this.settings.whitelisted_aws_account_principals.default;
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);
        var account = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);
        var listRoles = helpers.addSource(cache, source,
            ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                `Unable to query for IAM roles: ${helpers.addError(listRoles)}`);
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }

        var rolesFound = false;

        listRoles.data.forEach(role => {
            if (!role.AssumeRolePolicyDocument) return;

            var statements = helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument);
            var restrictedAccountPrincipals = [];
            var crossAccountRole = false;
            for (var s in statements) {
                var statement = statements[s];
                var principals = helpers.crossAccountPrincipal(statement.Principal, account, true);
                if (principals.length){
                    crossAccountRole = true;
                    rolesFound = true;
                    principals.forEach(principal => {
                        if (!whitelisted_aws_account_principals.includes(principal) &&
                                !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                    });
                }
            }

            if (crossAccountRole && !restrictedAccountPrincipals.length) {
                helpers.addResult(results, 0,
                    `Cross-account role "${role.RoleName}" contains trusted account pricipals`,
                    'global', role.Arn);
            }
            else if (crossAccountRole) {
                helpers.addResult(results, 2,
                    `Cross-account role "${role.RoleName}" contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`,
                    'global', role.Arn);
            }
        });

        if (!rolesFound) {
            helpers.addResult(results, 0, 'No cross-account IAM roles found', 'global');
        }
        
        callback(null, results, source);
    }
};