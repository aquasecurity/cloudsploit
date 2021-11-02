var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RAM Administrator Policies',
    category: 'RAM',
    description: 'Ensure that RAM policies which allow administrator access ("*:*") are not attached to RAM users, groups or roles.',
    more_info: 'RAM policies represent permissions that can be granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege. ' +
        'Determine what users need to do and then create policies with permissions only fits those tasks, instead of allowing full administrative privileges',
    link: 'https://www.alibabacloud.com/help/doc-detail/116815.htm',
    recommended_action: 'Ensure that administator RAM policies are not attached with any RAM resource.',
    apis: ['RAM:ListPolicies', 'RAM:GetPolicy', 'STS:GetCallerIdentity'],
    settings: {
        ram_policies_ignore_name: {
            name: 'RAM Policies Ignore Name',
            description: 'A comma-separated list indicating policy name which should be ignored without checking',
            regex: '^[0-9A-Za-z/._-]{3,512}$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            ram_policies_ignore_name: settings.ram_policies_ignore_name || this.settings.ram_policies_ignore_name.default
        };

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);

        var listPolicies = helpers.addSource(cache, source,
            ['ram', 'ListPolicies', region]);

        if (!listPolicies) return callback(null, results, source);

        if (listPolicies.err || !listPolicies.data) {
            helpers.addResult(results, 3,
                'Unable to query RAM policies' + helpers.addError(listPolicies), region);
            return callback(null, results, source);
        }

        if (!listPolicies.data.length) {
            helpers.addResult(results, 0, 'No RAM policies found', region);
            return callback(null, results, source);
        }

        for (let policy of listPolicies.data) {
            if (!policy.PolicyName || !policy.PolicyType || config.ram_policies_ignore_name.includes(policy.PolicyName)) continue;
            if (policy.PolicyType && policy.PolicyType.toUpperCase() == 'SYSTEM' && policy.PolicyName.toUpperCase() != 'ADMINISTRATORACCESS') continue;

            let resource = helpers.createArn('ram', accountId, `${policy.PolicyType.toLowerCase()}policy`, policy.PolicyName);
            let getPolicy = helpers.addSource(cache, source,
                ['ram', 'GetPolicy', region, policy.PolicyName]);

            if (!getPolicy || getPolicy.err || !getPolicy.data || !getPolicy.data.PolicyDocument) {
                helpers.addResult(results, 3,
                    `Unable to get RAM policy: ${getPolicy.err}`, region, resource);
            } else {
                let statements = helpers.normalizePolicyDocument(getPolicy.data.PolicyDocument);
                let attachmentCount = (policy.AttachmentCount) ? policy.AttachmentCount : 0;
                let adminPolicy = false;
                for (let statement of statements) {
                    if (statement.Effect && statement.Effect.toUpperCase() == 'ALLOW' &&
                        statement.Action && statement.Action.includes('*') &&
                        statement.Resource && statement.Resource.includes('*')) {
                        adminPolicy = true;
                        break;
                    }
                }

                if (adminPolicy && attachmentCount > 0) {
                    helpers.addResult(results, 2,
                        `Policy provides admin (*:*) access and attachment count is ${attachmentCount}`, region, resource);
                } else if (adminPolicy) {
                    helpers.addResult(results, 0,
                        `Policy provides admin (*:*) access but attachment count is ${attachmentCount}`, region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Policy does not provide admin (*:*) access', region, resource);
                }
            }
        }

        callback(null, results, source);
    }
};