var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WorkSpaces Healthy Instances',
    category: 'WorkSpaces',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that the AWS WorkSpace have healthy instances.',
    more_info: 'Amazon WorkSpace should have healthy and running instances to ensure proper connection. The WorkSpace is marked as Unhealthy if  response isn’t received from the WorkSpace in a timely manner.',
    recommended_action: 'Troubleshoot and resolve the unhealthy workspace issues.',
    link: 'https://docs.aws.amazon.com/workspaces/latest/adminguide/cloudwatch-dashboard.html',
    apis: ['WorkSpaces:describeWorkspaces','STS:getCallerIdentity'],
    realtime_triggers: ['workspaces:CreateWorkspaces','workspaces:DeleteWorkspaces'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaces', region]);

            if (!listWorkspaces)  return rcb();

            if (!listWorkspaces || listWorkspaces.err || !listWorkspaces.data) {
                helpers.addResult(results, 3,
                    'Unable to list Workspaces: ' + helpers.addError(listWorkspaces), region);
                return rcb();
            }
            
            if (!listWorkspaces.data.length) {
                helpers.addResult(results, 0,
                    'No WorkSpaces instances found', region);
                return rcb();
            }
            listWorkspaces.data.forEach(workspace => {
                if (!workspace.WorkspaceId) return;

                let resource = `arn:${awsOrGov}:region:${region}:${accountId}:worskpace/${workspace.WorkspaceId}`;

                if (workspace.State === 'UNHEALTHY') {
                    helpers.addResult(results, 2,
                        'Workspace instance is not in healthy state', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'WorkSpace instance is in healthy state', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
