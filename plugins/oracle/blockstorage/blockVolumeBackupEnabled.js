var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Block Volume Backup Enabled',
    category: 'Block Storage',
    description: 'Ensures block volumes have backups enabled.',
    more_info: 'Enabling block volume backup policies ensures that the block volume can be restored following in the event of data loss.',
    recommended_action: 'Enable backups on each block volume.',
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

                var blockVolumeBackupPolicies = helpers.addSource(cache, source,
                    ['volumeBackupPolicyAssignment', 'volume', region]);

                if (!blockVolumeBackupPolicies) return rcb();

                if ((blockVolumeBackupPolicies.err && blockVolumeBackupPolicies.err.length) || !blockVolumeBackupPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for block volume backups: ' + helpers.addError(blockVolumeBackupPolicies), region);
                    return rcb();
                }

                blockVolumeBackupPolicies.data.forEach(blockVolumeBackupPolicy => {
                    var bootIdx = badBlockVolumes.indexOf(blockVolumeBackupPolicy.assetId);

                    if (bootIdx > -1) {
                        badBlockVolumes.splice(bootIdx, 1);
                    }
                });

                if (badBlockVolumes.length) {
                    var badBlockVolumesStr = badBlockVolumes.join(', ');
                    helpers.addResult(results, 2,
                        `The following block volumes do not have a backup policy enabled: ${badBlockVolumesStr}`, region);
                } else {
                    helpers.addResult(results, 0,
                        'All block volumes have a backup policy enabled', region);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
