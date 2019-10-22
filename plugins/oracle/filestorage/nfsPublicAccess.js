var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'NFS Public Access',
    category: 'File Storage',
    description: 'Ensures that all File Systems do not have public access.',
    more_info: 'All Network File Systems should be configured to only allow access from trusted sources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/File/Tasks/exportoptions.htm',
    recommended_action: '1. Enter the File Storage service. 2. Enter the File System service 3. Select the File System. 4. Select the export. 5. Ensure that the source is not 0.0.0.0/0, if so edit the NFS Export Options to not allow public access.',
    apis: ['exportSummary:list','exprt:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.loadBalancer, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var fileSystems = helpers.addSource(cache, source,
                    ['exprt', 'get', region]);

                if (!fileSystems) return rcb();

                if ((fileSystems.err && fileSystems.err.length) || !fileSystems.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for File Systems: ' + helpers.addError(fileSystems), region);
                    return rcb();
                }

                if (!fileSystems.data.length) {
                    helpers.addResult(results, 0, 'No File Systems present', region);
                    return rcb();
                }

                fileSystems.data.forEach(fileSystem => {
                    var isPublic = false;
                    if (fileSystem.exportOptions) {
                        fileSystem.exportOptions.forEach(exportOption => {
                            if (exportOption.source == "0.0.0.0/0") {
                                isPublic = true;
                            };
                        });
                    };
                    if (isPublic) {
                        helpers.addResult(results, 2, 'NFS allows public access', region, fileSystem.fileSystemId);
                        return;
                    } else {
                        helpers.addResult(results, 0, 'NFS does not allow public access', region, fileSystem.fileSystemId);
                        return;
                    };
                });
            }
        });
        callback(null, results, source);
    }
};