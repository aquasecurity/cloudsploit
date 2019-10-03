var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Block Volume Backup Enabled',
    category: 'Block Storage',
    description: 'Determine if Block Volumes have backups enabled.',
    more_info: 'Enabling Block Volume backup policies ensures that the block volume can be restored following in the event of data loss.',
    recommended_action: '1. Enter the Block Volume Service. 2. Select the Block Volume in question. 3. Select Assign next to Backup Policy. 4. Select the best policy for your services.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumebackups.htm',
    apis: ['volume:list','volumeBackupPolicyAssignment:volume'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.volume, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var blockVolumes = helpers.addSource(cache, source,
                    ['volume', 'list', region]);

                if (!blockVolumes) return rcb();

                if ((blockVolumes.err && blockVolumes.err.length) || !blockVolumes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Block Volumes: ' + helpers.addError(blockVolumes), region);
                    return rcb();
                };

                if (!blockVolumes.data.length) {
                    helpers.addResult(results, 0, 'No Block Volumes present', region);
                    return rcb();
                };


                var myBlockVolumes = [];
                blockVolumes.data.forEach(blockVolume => {
                    myBlockVolumes.push(blockVolume.id);
                });

                var blockVolumeBackupPolicies = helpers.addSource(cache, source,
                    ['volumeBackupPolicyAssignment', 'volume', region]);

                if (!blockVolumeBackupPolicies) return rcb();

                if ((blockVolumeBackupPolicies.err && blockVolumeBackupPolicies.err.length) || !blockVolumeBackupPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Block Volume Backups: ' + helpers.addError(blockVolumeBackupPolicies), region);
                    return rcb();
                };

                blockVolumeBackupPolicies.data.forEach(blockVolumeBackupPolicy => {
                    var bootIdx = myBlockVolumes.indexOf(blockVolumeBackupPolicy.assetId)

                    if (bootIdx > -1) {
                        myBlockVolumes.splice(bootIdx, 1);
                    };
                });

                if (myBlockVolumes.length) {
                    var myBlockVolumesStr = myBlockVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following Block Volumes do not have a backup policy enabled: ${myBlockVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Block Volumes have a backup policy enabled', region);
                };
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
