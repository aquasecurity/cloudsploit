var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Enable All Organization Features',
    category: 'Organizations',
    description: 'Ensures all Organization features are enabled',
    more_info: 'All AWS Organizations should be enabled to take advantage of all shared security controls and policies across all member accounts.',
    recommended_action: 'Enable all AWS Organizations features.',
    link: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html?icmpid=docs_orgs_console',
    apis: ['Organizations:describeOrganization'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);
        var describeOrganization = helpers.addSource(cache, source, ['organizations', 'describeOrganization', region]);

        if (!describeOrganization.data || describeOrganization.err) {
            if (!describeOrganization.err || describeOrganization.err.code !== 'AWSOrganizationsNotInUseException') {
                helpers.addResult(results, 3, 'Cannot describe the organization', 'global');
            }
            return callback(null, results, source);
        }

        if (describeOrganization.data.FeatureSet !== 'ALL') {
            helpers.addResult(results, 2, 'Not all Organization features are enabled', 'global', describeOrganization.data.MasterAccountArn);
        } else {
            helpers.addResult(results, 0, 'All Organization features are enabled', 'global', describeOrganization.data.MasterAccountArn);
        }

        callback(null, results, source);
    }
};
