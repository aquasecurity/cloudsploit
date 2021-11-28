var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WorkSpaces Instance Count',
    category: 'WorkSpaces',
    domain: 'Identity Access and Management',
    description: 'Ensure that the number of Amazon WorkSpaces provisioned in your AWS account has not reached set limit.',
    more_info: 'In order to manage your WorkSpaces compute resources efficiently and prevent unexpected charges on your AWS bill, monitor and configure limits for the maximum number of WorkSpaces instances provisioned within your AWS account.',
    recommended_action: 'Ensure that number of WorkSpaces created within your AWS account is within set limit',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-limits.html',
    apis: ['WorkSpaces:describeWorkspaces'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var instanceCount = 0;
        const RECOMMENDED_THRESHOLD = 50;

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

            if (!listWorkspaces) {
                return rcb();
            }

            if (listWorkspaces.err || !listWorkspaces.data) {
                return rcb();
            }

            instanceCount += listWorkspaces.data.length;

            return rcb();
        }, function(){
            if (instanceCount > RECOMMENDED_THRESHOLD){
                helpers.addResult(results, 2, `Workspaces Instance count is greater then the recommended threshold
                                                i.e. ${RECOMMENDED_THRESHOLD} workspaces`);
            } else {
                helpers.addResult(results, 0, 'Workspaces Instance count is within the recommended threshold');
            }

            callback(null, results, source);
        });
    }
};
