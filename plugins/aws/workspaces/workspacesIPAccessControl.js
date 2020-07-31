var async = require("async");
var helpers = require("../../../helpers/aws");

module.exports = {
    title: "Workspaces IP Access Control",
    category: "Workspaces",
    description: "Ensures enforced IP Access Control on Workspaces",
    more_info: "Checking the existence of IP Access control on Workspaces and no open IP to any Workspaces",
    link: "https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-ip-access-control-groups.html",
    recommended_action: "Enable proper IP Access Controls for all workspaces",
    apis: ["WorkSpaces:describeWorkspaces", "WorkSpaces:describeWorkspaceDirectories", "WorkSpaces:describeIpGroups", "STS:getCallerIdentity"],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ["sts", "getCallerIdentity", acctRegion, "data"]);

        const enabledString = "IP Access Control enabled.";
        const disabledString = "IP Access Control not enabled.";

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ["workspaces", "describeWorkspaces", region, "data"]);
            var listDirectories = helpers.addSource(cache, source, ["workspaces", "describeWorkspaceDirectories", region, "data"]);
            var listIPGroups = helpers.addSource(cache, source, ["workspaces", "describeIpGroups", region, "data"]);

            if (!listWorkspaces) {
                return rcb()
            }

            if (listWorkspaces.err) {
                helpers.addResult(
                    results, 3, "Unable to query for WorkSpaces information: " + helpers.addError(listWorkspaces), region
                );
                return rcb()
            }

            if (!listWorkspaces.length) {
                helpers.addResult(
                    results, 0, "No Workspaces found.", region
                );
                return rcb()
            }

            for (var workspace of listWorkspaces) {
                var arn = "arn:" + awsOrGov + ":workspaces:" + region + ":" + accountId + ":workspace/" + workspace.WorkspaceId;

                if (!(workspace.DirectoryId)){
                    helpers.addResult(
                        results, 2, disabledString, region, arn
                    );
                }

                if (workspace){
                    var workspaceDirectory = listDirectories.find(directory => directory.DirectoryId === workspace.DirectoryId);
                    if (workspaceDirectory.ipGroupIds) {
                        let openIP = []
                        for (var workspaceIPGroup of workspaceDirectory.ipGroupIds){
                            var ipGroup = listIPGroups.find(o => o.groupId === workspaceIPGroup);

                            if (ipGroup.userRules) {
                                var queryIPGroup = ipGroup.userRules.find(o => o.ipRule === "0.0.0.0/0");
                                if (queryIPGroup){
                                    openIP.push('disabled')
                                } else {
                                    openIP.push('enabled')
                                }
                            } else {
                                openIP.push('enabled')
                            }

                        }
                        var ipOpen = openIP.find(o => o === 'disabled');

                        if (ipOpen){
                            helpers.addResult(
                                results, 2, disabledString, region, arn
                            );
                        } else {
                            helpers.addResult(
                                results, 0, enabledString, region, arn
                            );
                        }
                    } else {
                        helpers.addResult(
                            results, 2, disabledString, region, arn
                        );
                    }
                }
            }

            rcb();

        }, function(){
            callback(null, results, source);
        });
    }
}