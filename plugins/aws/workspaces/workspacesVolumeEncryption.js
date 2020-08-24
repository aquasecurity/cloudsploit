var async = require("async");
var helpers = require("../../../helpers/aws");

module.exports = {
    title: "Workspaces Volume Encryption",
    category: "Workspaces",
    description: "Ensures volume encryption on Workspaces",
    more_info: "Checking the existence of volume encryption on different volumes of Workspaces",
    link: "https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
    recommended_action: "Enable encryption for all workspaces",
    apis: ["WorkSpaces:describeWorkspaces", "STS:getCallerIdentity","KMS:describeKey", "KMS:listKeys", "KMS:listAliases"],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var accountId = helpers.addSource(cache, source, ["sts", "getCallerIdentity", acctRegion, "data"]);

        const enabledString = "Volume encryption enabled on User and Root volumes.";
        const enabledUser = "Volume encryption enabled on User volume but not on Root volume.";
        const enabledRoot = "Volume encryption enabled on Root volume but not on User volume.";
        const disabledString = "Volume encryption not enabled on any volumes.";
        const unknownStatusString = "Unable to obtain encryption status of volumes.";

        async.each(regions.workspaces, function(region, rcb){
            var listWorkspaces = helpers.addSource(cache, source, ["workspaces", "describeWorkspaces", region, "data"]);
            var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

            if (!listWorkspaces) {
                return rcb()
            }

            if (listWorkspaces.err) {
                helpers.addResult(results, 3, "Unable to query for WorkSpaces information: " + helpers.addError(listWorkspaces), region);
                return rcb()
            }

            if (listKeys.err || !listKeys.data){
                helpers.addResult(results, 3, "Unable to get keys" + helpers.addError(listKeys), region);
                return rcb()
            }

            if (!listWorkspaces.length) {
                helpers.addResult(results, 0, "No Workspaces found.", region);
                return rcb()
            }

            for (var workspace of listWorkspaces) {
                var arn = "arn:" + awsOrGov + ":workspaces:" + region + ":" + accountId + ":workspace/" + workspace.WorkspaceId;

                if (workspace.UserVolumeEncryptionEnabled && workspace.RootVolumeEncryptionEnabled){
                    if (workspace.VolumeEncryptionKey.includes('alias/')){
                        var getAliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
                        if (getAliases.err || !getAliases.data){
                            helpers.addResult(results, 3, "Unable to get aliases", region, arn);
                        } else {
                            var queryAlias = getAliases.data.find(alias => alias.AliasArn === workspace.VolumeEncryptionKey);
                            if (!queryAlias){
                                var aliasName = workspace.VolumeEncryptionKey.slice(workspace.VolumeEncryptionKey.search('alias/'), workspace.VolumeEncryptionKey.length);
                                helpers.addResult(results, 3, `Unable to locate Alias: ${aliasName}`, region, arn);
                            } else {
                                var queryKey = listKeys.data.find(key => key.KeyId === queryAlias.TargetKeyId);
                                if (!queryKey){
                                    helpers.addResult(results, 3, `Unable to locate Key for Alias: ${aliasName}`, region, arn);
                                } else {
                                    helpers.addResult(results, 0, enabledString, region, arn);
                                }}}
                    } else {
                        var queryKey = listKeys.data.find(key => key.KeyArn === workspace.VolumeEncryptionKey);
                        if (queryKey){
                            helpers.addResult(results, 0, enabledString, region, arn);
                        } else {
                            helpers.addResult(results, 3, unknownStatusString, region, arn);
                        }
                    }
                } else  if (workspace.UserVolumeEncryptionEnabled && !workspace.RootVolumeEncryptionEnabled){
                    helpers.addResult(results, 2, enabledUser, region, arn);
                } else if (!workspace.UserVolumeEncryptionEnabled && workspace.RootVolumeEncryptionEnabled){
                    helpers.addResult(results, 2, enabledRoot, region, arn);
                } else if (!workspace.UserVolumeEncryptionEnabled && !workspace.RootVolumeEncryptionEnabled){
                    helpers.addResult(results, 2, disabledString, region, arn);
                } else {
                    helpers.addResult(results, 3, unknownStatusString, region, arn);
                }
            }
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}