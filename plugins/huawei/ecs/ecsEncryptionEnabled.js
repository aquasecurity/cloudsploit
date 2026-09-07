'use strict';

module.exports = {
    title: 'Huawei ECS Disk Encryption Enabled',
    category: 'ECS',
    description: 'Checks if ECS instance disks have encryption enabled.',
    apis: ['ListServersDetails'],
    check: function(collection, callback) {
        //console.log('DEBUG: ecsEncryptionEnabled plugin called with collection:', JSON.stringify(collection, null, 2));

        const results = [];
        const servers = (collection.ecs && collection.ecs.servers) || [];

        if (!servers.length) {
            results.push({
                resource: 'N/A',
                region: 'global',
                status: 0,
                message: 'No ECS instances found'
            });
        } else {
            servers.forEach(server => {
                const unencryptedDisks = server.disks.filter(disk => !disk.encrypted).map(disk => disk.volumeId);
                if (unencryptedDisks.length) {
                    results.push({
                        resource: server.name,
                        region: 'global',
                        status: 2, // FAIL
                        message: `ECS instance has unencrypted disks: ${unencryptedDisks.join(', ')}`
                    });
                } else {
                    results.push({
                        resource: server.name,
                        region: 'global',
                        status: 0, // PASS
                        message: 'All disks are encrypted'
                    });
                }
            });
        }

        //console.log('DEBUG: ecsEncryptionEnabled results:', JSON.stringify(results, null, 2));
        callback(null, results);
    }
};
