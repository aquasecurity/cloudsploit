var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Support Policy',
    category: 'IAM',
    description: 'Ensures that an IAM role, group or user exists with specific permissions to access support center.',
    more_info: 'AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. An IAM Role should be present to allow authorized users to manage incidents with AWS Support.',
    link: 'https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html',
    recommended_action: 'Ensure that an IAM role has permission to access support center.',
    apis: ['IAM:listPolicies'],

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

        if (!listPolicies.data.length) {
            helpers.addResult(results, 0,
                'No IAM policies found');
            return callback(null, results, source);
        }

        var found = listPolicies.data.find(policy => policy.PolicyName == 'AWSSupportAccess');

        if (found) {
            helpers.addResult(results, 0,
                'AWSSupportAccess policy is attached to a user, role or group', 'global', found.Arn);
        } else {
            helpers.addResult(results, 2,
                'No role, user or group attached to the AWSSupportAccess policy', 'global');
        }

        callback(null, results, source);
    }
};
