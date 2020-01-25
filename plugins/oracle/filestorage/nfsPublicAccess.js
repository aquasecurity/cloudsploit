var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'NFS Public Access',
    category: 'File Storage',
    description: 'Ensures that all File Systems do not have public access.',
    more_info: 'All Network File Systems should be configured to only allow access from trusted sources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/File/Tasks/exportoptions.htm',
    recommended_action: '1. Enter the File Storage service. 2. Enter the File System service 3. Select the File System. 4. Select the export. 5. Ensure that the source is not 0.0.0.0/0, if so edit the NFS Export Options to not allow public access.',
    apis: ['exportSummary:list','exprt:get','mountTarget:list', 'vcn:list', 'subnet:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.exprt, function(region, rcb){

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
                var publicFileSystem = {};
                var mountSubnets = {};
                fileSystems.data.forEach(fileSystem => {
                    if (fileSystem.exportOptions) {
                        fileSystem.exportOptions.forEach(exportOption => {
                            if (exportOption.source === "0.0.0.0/0") {
                                publicFileSystem[fileSystem.exportSetId] = [];
                                publicFileSystem[fileSystem.exportSetId] = fileSystem.fileSystemId;
                            } else {
                                helpers.addResult(results, 0, 'NFS does not allow public access', region, fileSystem.fileSystemId);
                            }
                        });
                    }
                });
                var publicExportSets = Object.keys(publicFileSystem);
                 if (publicExportSets.length) {
                     var mountTargets = helpers.addSource(cache, source,
                         ['mountTarget', 'list', region]);

                     if ((mountTargets.err && mountTargets.err.length) || !mountTargets.data || !mountTargets.data.length) {
                         var publicFileSystemStr = Object.values(publicFileSystem).join(', ');
                         helpers.addResult(results, 2, `The following NFS allow public access: ${publicFileSystemStr}`, region);
                     } else {
                         mountTargets.data.forEach(mountTarget => {
                             if (publicExportSets > 1) {
                                if (publicExportSets.indexOf(mountTarget.exportSetId) > -1) {
                                    mountSubnets[mountTarget.subnetId] = publicFileSystem[mountTarget.exportSetId];
                                }
                             } else {
                                if (publicExportSets[0] === mountTarget.exportSetId) {
                                    mountSubnets[mountTarget.subnetId] = publicFileSystem[mountTarget.exportSetId];
                                }
                             }
                         });
                         var subnetsToCheck = Object.keys(mountSubnets);
                         if (subnetsToCheck.length) {

                             var subnets = helpers.addSource(cache, source,
                                 ['subnet', 'list', region]);

                             if ((subnets.err && subnets.err.length) || !subnets.data || !subnets.data.length) {
                                 helpers.addResult(results, 3,
                                 'Unable to query for Subnets: ' + helpers.addError(subnets))
                             } else {
                                 subnets.data.forEach(subnet => {
                                     if (subnetsToCheck.indexOf(subnet.id) > -1) {
                                         if (subnet.prohibitPublicIpOnVnic) {
                                             helpers.addResult(results, 0, 'NFS is in a private subnet and does not allow public access', region, mountSubnets[subnet.id]);
                                         } else {
                                             helpers.addResult(results, 2, 'NFS allows public access', region, mountSubnets[subnet.id]);
                                         }
                                     }
                                 })
                             }
                         } else {
                             var publicFileSystemStr = Object.values(publicFileSystem).join(', ');
                             helpers.addResult(results, 2, `The following NFS allow public access: ${publicFileSystemStr}`, region);
                         }
                     }
                 }

            }
        });
        callback(null, results, source);
    }
};