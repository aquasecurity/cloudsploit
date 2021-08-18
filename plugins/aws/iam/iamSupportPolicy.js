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
    
            if (listEntitiesForPolicy.err || !listEntitiesForPolicy[policyArn] || !listEntitiesForPolicy[policyArn].data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM entities for policy: ' + helpers.addError(listEntitiesForPolicy));
                return callback(null, results, source);
            }
    
            const attachments = [];
            addAttachments(attachments, listEntitiesForPolicy[policyArn].data);
            if (!attachments.length) {
                helpers.addResult(results, 2,
                    'No role, user or group attached to the policy', 'global', policyArn);
            } else {
                helpers.addResult(results, 0,
                    attachments.join(', '), 'global', policyArn);  
            }
        }
        return callback(null, results, source);
    }
};

const addAttachments = (attachments, entities) => {
    if ('PolicyGroups' in entities) {
        if (entities.PolicyGroups.length > 0 ) entities.PolicyGroups.forEach(
            group => attachments.push(`Policy is attached '${group.GroupName}' group`));        
    }
    if ('PolicyRoles' in entities) {
        if (entities.PolicyRoles.length > 0) entities.PolicyRoles.forEach(
            role => attachments.push(`Policy is attached '${role.RoleName}' role`));
    }
    if ('PolicyUsers' in entities) {
        if (entities.PolicyGroups.length > 0) entities.PolicyUsers.forEach(
            user => attachments.push(`Policy is attached '${user.UserName}' user`));
    }
};
