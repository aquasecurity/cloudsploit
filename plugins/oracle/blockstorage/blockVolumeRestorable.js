var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Block Volume Restorable',
    category: 'Block Storage',
    description: 'Ensures block volumes can be restored to a recent point.',
    more_info: 'Having recent backups on block volumes prevents data loss in the case of a catastrophe.',
    recommended_action: 'Ensure block volumes have recent backups to prevent data loss.',
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
                        'Unable to query for block volumes: ' + helpers.addError(blockVolumes), region);
                    return rcb();
                }

                if (!blockVolumes.data.length) {
                    helpers.addResult(results, 0, 'No block volumes found', region);
                    return rcb();
                }


                var badBlockVolumes = [];
                blockVolumes.data.forEach(blockVolume => {
                    badBlockVolumes.push(blockVolume.id);
                });

                var blockVolumeBackups = helpers.addSource(cache, source,
                    ['volumeBackup', 'list', region]);

                if (!blockVolumeBackups) return rcb();

                if ((blockVolumeBackups.err && blockVolumeBackups.err.length) || !blockVolumeBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for block volume backups: ' + helpers.addError(blockVolumeBackups), region);
                    return rcb();
                }

                blockVolumeBackups.data.forEach(blockVolumeBackup => {
                    var bootIdx = badBlockVolumes.indexOf(blockVolumeBackup.volumeId);

                    if (blockVolumeBackup.lifecycleState &&
                        blockVolumeBackup.lifecycleState === 'TERMINATED') {
                        return;
                    } else if (bootIdx > -1) {
                        badBlockVolumes.splice(bootIdx, 1);
                    }
                });

                if (badBlockVolumes.length) {
                    var badBlockVolumesStr = badBlockVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following block volumes are not actively restorable: ${badBlockVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All block volumes are restorable.', region);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
