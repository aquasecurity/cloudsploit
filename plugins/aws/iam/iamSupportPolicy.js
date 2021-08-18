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
        
        if (!listPolicies) return callback(null, results, source);

        if (listPolicies.err || !listPolicies.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM policies: ' + helpers.addError(listPolicies));
            return callback(null, results, source);
        }

        var policyArn = '';
        for (const policy of listPolicies.data) {
            if (policy.PolicyName == 'AWSSupportAccess') {
                if (policy.AttachmentCount > 0) {
                    policyArn = policy.Arn;
                    break;
                } else {
                    helpers.addResult(results, 2,
                        'No role, user or group attached to the AWSSupportAccess policy', 'global', policy.Arn);
                    return callback(null, results, source);
                }
            }
        }

        if (policyArn){
            const listEntitiesForPolicy = helpers.addSource(cache, source,
                ['iam', 'listEntitiesForPolicy', region, policyArn]);

            if (!listEntitiesForPolicy) return callback(null, results, source);
    
            if (listEntitiesForPolicy.err || !listEntitiesForPolicy || !listEntitiesForPolicy.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM entities for policy: ' + helpers.addError(listEntitiesForPolicy));
                return callback(null, results, source);
            }
    
            const attachments = [];
            addAttachments(attachments, listEntitiesForPolicy.data);
            if (!attachments.length) {
                helpers.addResult(results, 2,
                    'No role, user or group attached to the AWSSupportAccess policy', 'global', policyArn);
            } else {
                helpers.addResult(results, 0,
                    `AWSSupportAccess Policy attached to ${attachments.join(', ')}`, 'global', policyArn);  
            }
        }
        return callback(null, results, source);
    }
};

const addAttachments = (attachments, entities) => {
    if (entities.PolicyGroups && entities.PolicyGroups.length) attachments.push('groups');
    if (entities.PolicyRoles && entities.PolicyRoles.length) attachments.push('roles');
    if (entities.PolicyUsers && entities.PolicyUsers.length) attachments.push('users');
};
