var async = require('async');
var helpers = require('../../../helpers/aws');


module.exports = {
    title: 'IAM Role Policies',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures IAM role policies are properly scoped with specific permissions',
    more_info: 'Policies attached to IAM roles should be scoped to least-privileged access and avoid the use of wildcards.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html',
    recommended_action: 'Ensure that all IAM roles are scoped to specific services and API calls.',
    apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:listAttachedRolePolicies', 'IAM:listPolicies',
        'IAM:getPolicy', 'IAM:getPolicyVersion', 'IAM:getRolePolicy', 'IAM:getRole'],
    settings: {
        iam_role_policies_ignore_path: {
            name: 'IAM Role Policies Ignore Path',
            description: 'A comma-separated list indicating role paths which should PASS without checking',
            regex: '^[0-9A-Za-z/._-]{3,512}$',
            default: ''
        },
        ignore_service_specific_wildcards: {
            name: 'Ignore Service Specific Wildcards',
            description: 'This allows enables you to allow attached policies (inline and managed) to use service specific wildcards in Action. ' +
                'Example: Consider a role has following inline policy' +
                `{
                "Version": "2012-10-17",
                "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "cognito-sync:*",
                                "cognito-identity:*"
                            ],
                            "Resource": [
                                "*"
                            ]
                        }
                ]
            }` +
                'If ignore_service_specific_wildcards is true, a PASS result will be generated. ' +
                'If ignore_service_specific_wildcards is false, a FAIL result will be generated.',
            regex: '^(true|false)$',
            default: 'false'
        },
        ignore_identity_federation_roles: {
            name: 'Ignore Identity Federation Roles',
            description: 'This setting allows you to skip IdP/SAML based roles ' +
                'i.e. if for a role, all trust relationship statements have "Action" either "sts:AssumeRoleWithWebIdentity" or "sts:AssumeRoleWithSAML" '+
                'and value for this setting is set to true, a PASS results will be generated.',
            regex: '^(true|false)$',
            default: 'false'
        },
        ignore_aws_managed_iam_policies: {
            name: 'Ignore AWS-Managed IAM Policies',
            description: 'If set to true, skip AWS-managed policies attached to the role with the exception of AWS-managed AdministratorAccess policy',
            regex: '^(true|false)$',
            default: 'false'
        },
        ignore_customer_managed_iam_policies: {
            name: 'Ignore Customer-Managed IAM Policies',
            description: 'If set to true, skip customer-managed policies attached to the role',
            regex: '^(true|false)$',
            default: 'false'
        },
        iam_role_policies_ignore_tag: {
            name: 'IAM Role Policies Ignore Tag',
            description: 'A comma-separated list of tags to ignore roles that contain the provided tag. Give key-value pair i.e. env:Finance, env:Accounts ',
            regex: '^.*$',
            default: ''
        },
        iam_policy_resource_specific_wildcards: {
            name: 'IAM Policy Resource Specific Wildcards',
            description: 'Allows policy resources to flag based on regular expression. All the resources in IAM policy, inline or managed, will be tested against this regex and if they don\'t pass the regex, they will be flagged by the plugin.',
            regex: '^.*$',
            default: '^.*$',
        },
        ignore_iam_policy_resource_wildcards: {
            name: 'IAM Role Policies Ignore Resource Specific Wildcards',
            description: 'Enable this setting to ignore resource wildcards i.e. \'"Resource": "*"\' in the IAM policy, which by default, are being flagged.',
            regex: '^(true|false)$',
            default: 'false'
        }
    },
    realtime_triggers: ['iam:CreateRole','iam:DeleteRole','iam:AttachRolePolicy','iam:DetachRolePolicy','iam:PutRolePolicy','iam:DeleteRolePolicy'],

    run: function(cache, settings, callback) {
        var config = {
            iam_role_policies_ignore_path: settings.iam_role_policies_ignore_path || this.settings.iam_role_policies_ignore_path.default,
            ignore_service_specific_wildcards: settings.ignore_service_specific_wildcards || this.settings.ignore_service_specific_wildcards.default,
            ignore_identity_federation_roles: settings.ignore_identity_federation_roles || this.settings.ignore_identity_federation_roles.default,
            ignore_aws_managed_iam_policies: settings.ignore_aws_managed_iam_policies || this.settings.ignore_aws_managed_iam_policies.default,
            ignore_customer_managed_iam_policies: settings.ignore_customer_managed_iam_policies || this.settings.ignore_customer_managed_iam_policies.default,
            iam_role_policies_ignore_tag: settings.iam_role_policies_ignore_tag || this.settings.iam_role_policies_ignore_tag.default,
            iam_policy_resource_specific_wildcards: settings.iam_policy_resource_specific_wildcards || this.settings.iam_policy_resource_specific_wildcards.default,
            ignore_iam_policy_resource_wildcards: settings.ignore_iam_policy_resource_wildcards || this.settings.ignore_iam_policy_resource_wildcards.default
        };

        config.ignore_service_specific_wildcards = (config.ignore_service_specific_wildcards === 'true');
        config.ignore_identity_federation_roles = (config.ignore_identity_federation_roles === 'true');
        config.ignore_aws_managed_iam_policies = (config.ignore_aws_managed_iam_policies === 'true');
        config.ignore_customer_managed_iam_policies = (config.ignore_customer_managed_iam_policies === 'true');
        config.ignore_iam_policy_resource_wildcards = (config.ignore_iam_policy_resource_wildcards === 'true');



        var allowedRegex = RegExp(config.iam_policy_resource_specific_wildcards);
        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var managedAdminPolicy = `arn:${awsOrGov}:iam::aws:policy/AdministratorAccess`;

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

            // Skip roles with user-defined paths
            if (config.iam_role_policies_ignore_path &&
                config.iam_role_policies_ignore_path.length &&
                role.Path &&
                role.Path.indexOf(config.iam_role_policies_ignore_path) > -1) {
                return cb();
            }
            // Get role details
            var getRole = helpers.addSource(cache, source,
                ['iam', 'getRole', region, role.RoleName]);

            if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM role details: ' + role.RoleName + ': ' + helpers.addError(getRole), 'global', role.Arn);
                return cb();
            }

            //Skip roles with user defined tags
            if (config.iam_role_policies_ignore_tag && config.iam_role_policies_ignore_tag.length) {
                var tagList = config.iam_role_policies_ignore_tag.split(',');
                var ignoreRole = tagList.some(tag => {
                    var key = tag.split(/:(?!.*:)/)[0].trim();
                    var value = new RegExp(tag.split(/:(?!.*:)/)[1].trim());
                    if (getRole.data.Role.Tags && getRole.data.Role.Tags.length){
                        return getRole.data.Role.Tags.find(tag =>
                            tag.Key == key && value.test(tag.Value));
                    }
                });
                if (ignoreRole) return cb();
            }

            if (config.ignore_identity_federation_roles &&
                helpers.hasFederatedUserRole(helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument))) {
                helpers.addResult(results, 0,
                    'Role is federated user role',
                    'global', role.Arn, custom);
                return cb();
            }

            // Get managed policies attached to role
            var listAttachedRolePolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedRolePolicies', region, role.RoleName]);

            // Get inline policies attached to role
            var listRolePolicies = helpers.addSource(cache, source,
                ['iam', 'listRolePolicies', region, role.RoleName]);

            var getRolePolicy = helpers.addSource(cache, source,
                ['iam', 'getRolePolicy', region, role.RoleName]);

            if (!listAttachedRolePolicies || listAttachedRolePolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for role: ' + role.RoleName + ': ' + helpers.addError(listAttachedRolePolicies), 'global', role.Arn);
                return cb();
            }

            if (!listRolePolicies || listRolePolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM role policy for role: ' + role.RoleName + ': ' + helpers.addError(listRolePolicies), 'global', role.Arn);
                return cb();
            }

            var roleFailures = [];

            // See if role has admin managed policy
            if (listAttachedRolePolicies.data &&
                listAttachedRolePolicies.data.AttachedPolicies) {

                for (var policy of listAttachedRolePolicies.data.AttachedPolicies) {
                    if (policy.PolicyArn === managedAdminPolicy) {
                        roleFailures.push('Role has managed AdministratorAccess policy');
                        break;
                    }

                    if (config.ignore_aws_managed_iam_policies && new RegExp(`^arn:${awsOrGov}:iam::aws:.*`).test(policy.PolicyArn)) continue;

                    if (config.ignore_customer_managed_iam_policies && new RegExp(`^arn:${awsOrGov}:iam::[0-9]{12}:.*`).test(policy.PolicyArn)) continue;

                    var getPolicy = helpers.addSource(cache, source,
                        ['iam', 'getPolicy', region, policy.PolicyArn]);

                    if (getPolicy &&
                        getPolicy.data &&
                        getPolicy.data.Policy &&
                        getPolicy.data.Policy.DefaultVersionId) {
                        var getPolicyVersion = helpers.addSource(cache, source,
                            ['iam', 'getPolicyVersion', region, policy.PolicyArn]);

                        if (getPolicyVersion &&
                            getPolicyVersion.data &&
                            getPolicyVersion.data.PolicyVersion &&
                            getPolicyVersion.data.PolicyVersion.Document) {
                            let statements = helpers.normalizePolicyDocument(
                                getPolicyVersion.data.PolicyVersion.Document);
                            if (!statements) break;

                            addRoleFailures(roleFailures, statements, 'managed', config.ignore_service_specific_wildcards, allowedRegex, config.ignore_iam_policy_resource_wildcards);
                        }
                    }
                }
            }

            if (listRolePolicies.data &&
                listRolePolicies.data.PolicyNames) {

                for (var p in listRolePolicies.data.PolicyNames) {
                    var policyName = listRolePolicies.data.PolicyNames[p];

                    if (getRolePolicy &&
                        getRolePolicy[policyName] &&
                        getRolePolicy[policyName].data &&
                        getRolePolicy[policyName].data.PolicyDocument) {

                        var statements = getRolePolicy[policyName].data.PolicyDocument;
                        if (!statements) break;
                        addRoleFailures(roleFailures, statements, 'inline', config.ignore_service_specific_wildcards, allowedRegex,  config.ignore_iam_policy_resource_wildcards);
                    }
                }
            }

            if (roleFailures.length) {
                helpers.addResult(results, 2,
                    roleFailures.join(', '),
                    'global', role.Arn, custom);
            } else {
                helpers.addResult(results, 0,
                    'Role does not have overly-permissive policy',
                    'global', role.Arn, custom);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};

function addRoleFailures(roleFailures, statements, policyType, ignoreServiceSpecific, regResource, ignoreResourceSpecific) {
    for (var statement of statements) {
        if (statement.Effect === 'Allow' &&
            !statement.Condition) {
            let failMsg;
            if (statement.Action &&
                statement.Action.indexOf('*') > -1 &&
                statement.Resource &&
                statement.Resource.indexOf('*') > -1) {
                failMsg = `Role ${policyType} policy allows all actions on all resources`;
            } else if (statement.Action.indexOf('*') > -1) {
                failMsg = `Role ${policyType} policy allows all actions on selected resources`;
            } else if (!ignoreResourceSpecific && statement.Resource && statement.Resource == '*' ){
                failMsg = `Role ${policyType} policy allows actions on all resources`;
            } else if (!ignoreServiceSpecific && statement.Action && statement.Action.length) {
                // Check each action for wildcards
                let wildcards = [];
                for (var a in statement.Action) {
                    if (/^.+:[a-zA-Z]?\*.?$/.test(statement.Action[a])) {
                        wildcards.push(statement.Action[a]);
                    }
                }
                if (wildcards.length) failMsg = `Role ${policyType} policy allows wildcard actions: ${wildcards.join(', ')}`;
            } else if (statement.Resource && statement.Resource.length) {
                // Check each resource for wildcard
                let wildcards = [];
                for (var resource of statement.Resource) {
                    if (!regResource.test(resource)) {
                        wildcards.push(resource);
                    }
                }
                if (wildcards.length) failMsg = `Role ${policyType} policy does not match provided regex: ${wildcards.join(', ')}`;
            }

            if (failMsg && roleFailures.indexOf(failMsg) === -1) roleFailures.push(failMsg);
        }
    }
}