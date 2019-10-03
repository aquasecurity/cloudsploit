var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Transit Encryption',
    category: 'Compute',
    description: 'Determine if in-transit data encryption is enabled on boot volumes.',
    more_info: 'Enabling Boot Volume in-transit data encryption ensures that Boot Volume data is secured and follows Oracle security best practices.',
    recommended_action: 'Boot Volume Transit Encryption can only be configured when creating a new instance. Recreate the instance with in-transit encryption enabled.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm',
    apis: ['bootVolumeAttachment:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bootVolumeAttachment, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var bootVolumeAttachments = helpers.addSource(cache, source,
                    ['bootVolumeAttachment', 'list', region]);

                if (!bootVolumeAttachments) return rcb();

                if ((bootVolumeAttachments.err && bootVolumeAttachments.err.length) || !bootVolumeAttachments.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Boot Volume Attachments: ' + helpers.addError(bootVolumeAttachments), region);
                    return rcb();
                };

                if (!bootVolumeAttachments.data.length) {
                    helpers.addResult(results, 0, 'No Boot Volume Attachments present', region);
                    return rcb();
                };

                bootVolumeAttachments.data.forEach(bootVolumeAttachment => {
                    if (bootVolumeAttachment.isPvEncryptionInTransitEnabled &&
                        bootVolumeAttachment.isPvEncryptionInTransitEnabled == true) {
                        helpers.addResult(results, 0, 'Boot Volume Transit Encryption is enabled', region, bootVolumeAttachment.bootVolumeId);
                    } else {
                        helpers.addResult(results, 2, 'Boot Volume Transit Encryption is disabled', region, bootVolumeAttachment.bootVolumeId);
                    };
                });
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};