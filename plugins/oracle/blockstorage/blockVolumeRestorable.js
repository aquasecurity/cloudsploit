var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Block Volume Restorable',
    category: 'Block Storage',
    description: 'Determine if Block Volumes can be restored to a recent point.',
    more_info: 'Ensuring that Block Volumes have an active backup prevents data loss in the case of a catastrophe.',
    recommended_action: '1. Enter the Block Volume Service. 2. Select the Block Volume in question. 3. Select Block Volume Backups from the lower left blade. 4. Create a manual backup.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumebackups.htm',
    apis: ['volume:list','volumeBackup:list'],

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

                var blockVolumeBackups = helpers.addSource(cache, source,
                    ['volumeBackup', 'list', region]);

                if (!blockVolumeBackups) return rcb();

                if ((blockVolumeBackups.err && blockVolumeBackups.err.length) || !blockVolumeBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Block Volume Backups: ' + helpers.addError(blockVolumeBackups), region);
                    return rcb();
                };

                blockVolumeBackups.data.forEach(blockVolumeBackup => {
                    var bootIdx = myBlockVolumes.indexOf(blockVolumeBackup.volumeId)

                    if (blockVolumeBackup.lifecycleState &&
                        blockVolumeBackup.lifecycleState == 'TERMINATED') {
                        return
                    } else if (bootIdx > -1) {
                        myBlockVolumes.splice(bootIdx, 1);
                    };
                });

                if (myBlockVolumes.length) {
                    var myBlockVolumesStr = myBlockVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following Block Volumes are not actively restorable: ${myBlockVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All Block Volumes are restorable.', region);
                };
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
