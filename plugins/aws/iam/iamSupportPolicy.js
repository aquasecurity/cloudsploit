var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Support Policy',
    category: 'IAM',
    description: 'Ensures that an IAM role, group or user exists with specific permissions to access support center',
    more_info: 'AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. An IAM Role should be present to allow authorized users to manage incidents with AWS Support',
    link: 'https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html',
    recommended_action: 'Ensure that an IAM role has permission to access support center.',
    apis: ['IAM:listPolicies', 'IAM:listEntitiesForPolicy'],
    settings: {},

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        const listPolicies = helpers.addSource(cache, source,
            ['iam', 'listPolicies', region]);
        
        const listEntitiesForPolicy = helpers.addSource(cache, source,
            ['iam', 'listEntitiesForPolicy', region]);
        
        if (!listPolicies) return callback(null, results, source);

        if (listPolicies.err || !listPolicies.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM policies: ' + helpers.addError(listPolicies));
            return callback(null, results, source);
        }

        var policyArn = '';
        listPolicies.data.forEach(policy => {
            if (policy.PolicyName == 'AWSSupportAccess') {
                if (policy.AttachmentCount > 0) {
                    policyArn = policy.Arn;
                } else {
                    helpers.addResult(results, 2,
                        'No role, user or group attached to the policy', 'global', policy.Arn);
                }
            }
        });
        if (policyArn){
            if (!listEntitiesForPolicy) return callback(null, results, source);
    
            if (listEntitiesForPolicy.err || !listEntitiesForPolicy.policyArn || !listEntitiesForPolicy[policyArn].data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM entities for policy: ' + helpers.addError(listEntitiesForPolicy));
                return callback(null, results, source);
            }
    
            const policyChecks = ['PolicyGroups', 'PolicyRoles', 'PolicyUsers'];
            const entities = listEntitiesForPolicy[policyArn].data;
    
            const filteredEntities = Object.entries(entities).filter(entity => entity in policyChecks && !entities[entity]);
    
            if (filteredEntities){
                const attachments = [];
                addAttachments(attachments, filteredEntities);
                helpers.addResult(results, 0,
                    attachments.join(', '), 'global', policyArn);         
            } else {
                helpers.addResult(results, 2,
                    'No role, user or group attached to the policy', 'global', policyArn);
            }
        }

        return callback(null, results, source);

    }
};

const addAttachments = (attachments, entities) => {
    
    if ('PolicyGroups' in entities) {
        if (entities.PolicyGroups){
            const attachedGroups = {
                groups: []
            };
            entities.PolicyGroups.forEach(group => attachedGroups.groups.push(group.GroupName));
            attachments.push(attachedGroups);
        }
        
    }
    if ('PolicyRoles' in entities) {
        if (entities.PolicyRoles){
            const attachedRoles = {
                roles: []
            };
            entities.PolicyRoles.forEach(role => attachedRoles.Roles.push(role.RoleName));
            attachments.push(attachedRoles);
        }
    }
    if ('PolicyUsers' in entities) {
        if (entities.PolicyGroups){
            const attachedUsers = {
                users: []
            };
            entities.PolicyUsers.forEach(user => attachedUsers.Users.push(user.UserName));
            attachments.push(attachedUsers);
        }
    }
};
