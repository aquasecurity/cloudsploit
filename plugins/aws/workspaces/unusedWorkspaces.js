var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused WorkSpaces',
    category: 'WorkSpaces',
    description: 'Ensure that there are no unused AWS WorkSpaces instances available within your AWS account.',
    more_info: 'An AWS WorkSpaces instance is considered unused if it has 0 known user connections registered within the past 30 days. Remove these instances to avoid unnecessary billing.',
    link: 'https://aws.amazon.com/workspaces/pricing/',
    recommended_action: 'Identify and remove unused Workspaces instance',
    apis: ['WorkSpaces:describeWorkspacesConnectionStatus','STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
       
        var awsOrGov = helpers.defaultPartition(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion , 'data']);

        async.each(regions.workspaces, function(region, rcb){
            var describeWorkspacesConnectionStatus = helpers.addSource(cache, source,
                ['workspaces', 'describeWorkspacesConnectionStatus', region]);

            if (!describeWorkspacesConnectionStatus) return rcb();

            if (describeWorkspacesConnectionStatus.err || !describeWorkspacesConnectionStatus.data) {
                helpers.addResult(results, 3,
                    'Unable to query for WorkSpaces instance connection status: ' + helpers.addError(describeWorkspacesConnectionStatus), region);
                return rcb();
            }

            if (!describeWorkspacesConnectionStatus.data.length) {   
                helpers.addResult(results, 0, 'No WorkSpaces instance connection status found', region);
                return rcb();
            }
            
            describeWorkspacesConnectionStatus.data.forEach(workspace => {
                if (!workspace.WorkspaceId) return;

                let resource = `arn:${awsOrGov}:region:${region}:${accountId}:worskpace/${workspace.WorkspaceId}`;

                if (!workspace.LastKnownUserConnectionTimestamp) {
                    helpers.addResult(results, 2,
                        'WorkSpace does not have any known user connection', region, resource);
                } else if (workspace.LastKnownUserConnectionTimestamp &&
                    (helpers.daysBetween(new Date(), workspace.LastKnownUserConnectionTimestamp)) > 30) {
                    helpers.addResult(results, 2,
                        `WorkSpace is not in use for last ${helpers.daysBetween(new Date(), workspace.LastKnownUserConnectionTimestamp)}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'WorkSpace is in use', region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
