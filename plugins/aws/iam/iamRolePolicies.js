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
            description: 'If set to true, skip customer-managed policies attached to the role.',
            regex: '^(true|false)$',
            default: 'false'
        },
        iam_role_policies_ignore_tag: {
            name: 'IAM Role Policies Ignore Tag',
            description: 'A comma-separated list of tags to ignore roles that contain the provided tag. Give key-value pair i.e. env:Finance, env:Accounts ',
            regex: '^.*$',
            default: ''
        },
        iam_policy_message_format: {
            name: 'IAM Policy Message Format',
            description: 'Enable this setting to include policy names in the failure messages',
            regex: '^(true|false)$',
            default: 'false'
        }
    },
    realtime_triggers: ['iam:CreateRole','iam:DeleteRole','iam:AttachRolePolicy','iam:DetachRolePolicy','iam:PutRolePolicy','iam:DeleteRolePolicy'],

    run: function(cache, settings, callback) {
        var config = {
            iam_role_policies_ignore_path: settings.iam_role_policies_ignore_path || this.settings.iam_role_policies_ignore_path.default,
            ignore_identity_federation_roles: settings.ignore_identity_federation_roles || this.settings.ignore_identity_federation_roles.default,
            ignore_aws_managed_iam_policies: settings.ignore_aws_managed_iam_policies || this.settings.ignore_aws_managed_iam_policies.default,
            ignore_customer_managed_iam_policies: settings.ignore_customer_managed_iam_policies || this.settings.ignore_customer_managed_iam_policies.default,
            iam_role_policies_ignore_tag: settings.iam_role_policies_ignore_tag || this.settings.iam_role_policies_ignore_tag.default,
            iam_policy_message_format: settings.iam_policy_message_format || this.settings.iam_policy_message_format.default
        };

        config.ignore_identity_federation_roles = (config.ignore_identity_federation_roles === 'true');
        config.ignore_aws_managed_iam_policies = (config.ignore_aws_managed_iam_policies === 'true');
        config.ignore_customer_managed_iam_policies = (config.ignore_customer_managed_iam_policies === 'true');
        config.iam_policy_message_format = (config.iam_policy_message_format === 'true');

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

                    var roleFailures = config.iam_policy_message_format ? {} : [];


                    // See if role has admin managed policy
                    if (listAttachedRolePolicies.data &&
                        listAttachedRolePolicies.data.AttachedPolicies) {

                        for (var policy of listAttachedRolePolicies.data.AttachedPolicies) {
                            if (policy.PolicyArn === managedAdminPolicy) {
                                if (config.iam_policy_message_format) {
                                    roleFailures.admin = 'managedAdminPolicy';
                                } else {
                                    roleFailures.push('Role has managed AdministratorAccess policy');
                                }
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

                                    if (config.iam_policy_message_format) {
                                        addRoleFailuresPolicyName(roleFailures, statements, 'managed', policy.PolicyName);
                                    } else {
                                        addRoleFailures(roleFailures, statements, 'managed');
                                    }
                                }
                            }
                        }
                    }

                    if (role.attachedPolicies && Array.isArray(role.attachedPolicies) && role.attachedPolicies.length) {
                        for (var enrichedPolicy of role.attachedPolicies) {
                            if (enrichedPolicy.PolicyArn === managedAdminPolicy) {
                                if (config.iam_policy_message_format) {
                                    roleFailures.admin = 'managedAdminPolicy';
                                } else {
                                    roleFailures.push('Role has managed AdministratorAccess policy');
                                }
                                break;
                            }

                            if (config.ignore_aws_managed_iam_policies && new RegExp(`^arn:${awsOrGov}:iam::aws:.*`).test(enrichedPolicy.PolicyArn)) continue;

                            if (config.ignore_customer_managed_iam_policies && new RegExp(`^arn:${awsOrGov}:iam::[0-9]{12}:.*`).test(enrichedPolicy.PolicyArn)) continue;

                            var enrichedGetPolicy = helpers.addSource(cache, source,
                                ['iam', 'getPolicy', region, enrichedPolicy.PolicyArn]);

                            if (enrichedGetPolicy &&
                                enrichedGetPolicy.data &&
                                enrichedGetPolicy.data.Policy &&
                                enrichedGetPolicy.data.Policy.DefaultVersionId) {
                                var enrichedGetPolicyVersion = helpers.addSource(cache, source,
                                    ['iam', 'getPolicyVersion', region, enrichedPolicy.PolicyArn]);

                                if (enrichedGetPolicyVersion &&
                                    enrichedGetPolicyVersion.data &&
                                    enrichedGetPolicyVersion.data.PolicyVersion &&
                                    enrichedGetPolicyVersion.data.PolicyVersion.Document) {
                                    let enrichedStatements = helpers.normalizePolicyDocument(
                                        enrichedGetPolicyVersion.data.PolicyVersion.Document);
                                    if (!enrichedStatements) break;

                                    if (config.iam_policy_message_format) {
                                        addRoleFailuresPolicyName(roleFailures, enrichedStatements, 'managed', enrichedPolicy.PolicyName);
                                    } else {
                                        addRoleFailures(roleFailures, enrichedStatements, 'managed');
                                    }
                                }
                            }
                        }
                    }

                    var processedInlinePolicies = new Set();

                    if (listRolePolicies.data &&
                        listRolePolicies.data.PolicyNames &&
                        listRolePolicies.data.PolicyNames.length) {

                        for (var p in listRolePolicies.data.PolicyNames) {
                            var policyName = listRolePolicies.data.PolicyNames[p];

                            if (getRolePolicy &&
                                getRolePolicy[policyName] &&
                                getRolePolicy[policyName].data &&
                                getRolePolicy[policyName].data.PolicyDocument) {

                                processedInlinePolicies.add(policyName);
                                var policyDoc = getRolePolicy[policyName].data.PolicyDocument;
                                var statements = Array.isArray(policyDoc) ? policyDoc : helpers.normalizePolicyDocument(policyDoc);
                                if (!statements) continue;
                                if (config.iam_policy_message_format) {
                                    addRoleFailuresPolicyName(roleFailures, statements, 'inline', policyName);
                                } else {
                                    addRoleFailures(roleFailures, statements, 'inline');
                                }
                            }
                        }
                    }

                    if (role.inlinePolicies && Array.isArray(role.inlinePolicies) && role.inlinePolicies.length) {
                        for (var enrichedInlinePolicy of role.inlinePolicies) {
                            if (!enrichedInlinePolicy || !enrichedInlinePolicy.PolicyDocument) continue;

                            var enrichedPolicyName = enrichedInlinePolicy.PolicyName;
                            if (processedInlinePolicies.has(enrichedPolicyName)) continue;

                            var enrichedPolicyDoc = enrichedInlinePolicy.PolicyDocument;
                            var enrichedStatementsInline = Array.isArray(enrichedPolicyDoc) ? enrichedPolicyDoc : helpers.normalizePolicyDocument(enrichedPolicyDoc);
                            if (!enrichedStatementsInline) continue;
                            if (config.iam_policy_message_format) {
                                addRoleFailuresPolicyName(roleFailures, enrichedStatementsInline, 'inline', enrichedPolicyName);
                            } else {
                                addRoleFailures(roleFailures, enrichedStatementsInline, 'inline');
                            }
                        }
                    }

                    if (config.iam_policy_message_format) {
                        compileFormattedResults(roleFailures, role, results, custom);
                    } else {
                        compileSimpleResults(roleFailures, role, results, custom);
                    }

            cb();
        }, function() {
            callback(null, results, source);
        });
    }
};

function addRoleFailures(roleFailures, statements, policyType) {
    for (var statement of statements) {
        if (statement.Effect === 'Allow') {
            let failMsg;
            if (statement.Action &&
                statement.Action.indexOf('*') > -1 &&
                statement.Resource &&
                statement.Resource.indexOf('*') > -1) {
                failMsg = `Role ${policyType} policy allows all actions on all resources`;
            } else if (statement.Action && statement.Action.indexOf('*') > -1) {
                failMsg = `Role ${policyType} policy allows all actions on selected resources`;
            }

            if (failMsg && roleFailures.indexOf(failMsg) === -1) roleFailures.push(failMsg);
        }
    }
}

function addRoleFailuresPolicyName(roleFailures, statements, policyType, policyName) {
    if (!roleFailures.managed) {
        roleFailures.managed = {
            allActionsAllResources: [],
            allActionsSelectedResources: [],
        };
    }
    if (!roleFailures.inline) {
        roleFailures.inline = {
            allActionsAllResources: [],
            allActionsSelectedResources: [],
        };
    }
    if (!roleFailures.admin) roleFailures.admin = false;

    for (var statement of statements) {
        if (statement.Effect === 'Allow') {
            let targetObj = roleFailures[policyType];

            if (statement.Action &&
                statement.Action.indexOf('*') > -1 &&
                statement.Resource &&
                statement.Resource.indexOf('*') > -1) {
                targetObj.allActionsAllResources.push(policyName);
            } else if (statement.Action && statement.Action.indexOf('*') > -1) {
                targetObj.allActionsSelectedResources.push(policyName);
            }
        }
    }
}

function hasFailures(roleFailures) {
    if (roleFailures.admin) return true;

    if (roleFailures.managed && roleFailures.managed.allActionsAllResources.length) return true;
    if (roleFailures.managed && roleFailures.managed.allActionsSelectedResources.length) return true;
    if (roleFailures.inline && roleFailures.inline.allActionsAllResources.length) return true;
    if (roleFailures.inline && roleFailures.inline.allActionsSelectedResources.length) return true;

    return false;
}

function formatPolicyNames(policyArray) {
    if (policyArray.length <= 5) {
        return [...new Set(policyArray)].join('", "');
    }
    return [...new Set(policyArray)].slice(0, 5).join('", "') + '" and so on...';
}

function compileSimpleResults(roleFailures, role, results, custom) {
    if (roleFailures.length) {
        helpers.addResult(results, 2,
            roleFailures.join(', '),
            'global', role.Arn, custom);
    } else {
        helpers.addResult(results, 0,
            'Role does not have overly-permissive policy',
            'global', role.Arn, custom);
    }
}

function compileFormattedResults(roleFailures, role, results, custom) {
    if (hasFailures(roleFailures)) {
        let messages = [];

        if (roleFailures.admin == 'managedAdminPolicy') {
            messages.push('Role has managed AdministratorAccess policy');
        }

        if (roleFailures.managed && roleFailures.managed.allActionsAllResources.length) {
            messages.push(`Role managed policy "${formatPolicyNames(roleFailures.managed.allActionsAllResources)}" allows all actions on all resources`);
        }

        if (roleFailures.managed && roleFailures.managed.allActionsSelectedResources.length) {
            messages.push(`Role managed policy "${formatPolicyNames(roleFailures.managed.allActionsSelectedResources)}" allows all actions on selected resources`);
        }

        if (roleFailures.inline && roleFailures.inline.allActionsAllResources.length) {
            messages.push(`Role inline policy "${formatPolicyNames(roleFailures.inline.allActionsAllResources)}" allows all actions on all resources`);
        }

        if (roleFailures.inline && roleFailures.inline.allActionsSelectedResources.length) {
            messages.push(`Role inline policy "${formatPolicyNames(roleFailures.inline.allActionsSelectedResources)}" allows all actions on selected resources`);
        }

        helpers.addResult(results, 2,
            messages.join('\n'),
            'global', role.Arn, custom);
    } else {
        helpers.addResult(results, 0,
            'Role does not have full "*:*" administrative policy',
            'global', role.Arn, custom);
    }
}