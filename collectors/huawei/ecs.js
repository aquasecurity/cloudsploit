'use strict';

const { EcsClient, ListServersDetailsRequest } = require('@huaweicloud/huaweicloud-sdk-ecs');
const { EvsClient, ShowVolumeRequest } = require('@huaweicloud/huaweicloud-sdk-evs');
const { BasicCredentials } = require('@huaweicloud/huaweicloud-sdk-core');

module.exports = function(cloudConfig, callback) {
    //console.log('DEBUG: Starting ECS collection with config:', JSON.stringify(cloudConfig, null, 2));

    // Validate required config fields
    if (!cloudConfig.accessKeyId || !cloudConfig.secretAccessKey) {
        const err = new Error('Missing accessKeyId or secretAccessKey in cloudConfig');
        console.error('ERROR: ECS collector validation failed:', err.message);
        return callback(err);
    }

    try {
        // Initialize credentials
        const credentials = new BasicCredentials()
            .withAk(cloudConfig.accessKeyId)
            .withSk(cloudConfig.secretAccessKey)
            .withProjectId(cloudConfig.projectId || '');

        // Create the ECS client
        const ecsEndpoint = `https://ecs.${cloudConfig.region}.myhuaweicloud.com`;
        //console.log('DEBUG: Using ECS endpoint:', ecsEndpoint);
        const ecsClient = EcsClient.newBuilder()
            .withCredential(credentials)
            .withEndpoint(ecsEndpoint)
            .build();

        // Create the EVS client
        const evsEndpoint = `https://evs.${cloudConfig.region}.myhuaweicloud.com`;
        //console.log('DEBUG: Using EVS endpoint:', evsEndpoint);
        const evsClient = EvsClient.newBuilder()
            .withCredential(credentials)
            .withEndpoint(evsEndpoint)
            .build();

        // Create the request for ListServersDetails
        //console.log('DEBUG: Calling ListServersDetails API...');
        const request = new ListServersDetailsRequest();
        ecsClient.listServersDetails(request)
            .then(listServersResult => {
                //console.log('DEBUG: Raw listServersDetails response:', JSON.stringify(listServersResult, null, 2));

                const servers = listServersResult.servers || [];
                //console.log('DEBUG: Found', servers.length, 'ECS instances');

                // Process each server and fetch disk encryption status
                const serverPromises = servers.map(server => {
                    const volumes = server['os-extended-volumes:volumes_attached'] || [];
                    //console.log(`DEBUG: Volumes for server ${server.id}:`, JSON.stringify(volumes, null, 2));

                    // Fetch encryption status for each volume
                    const diskPromises = volumes.map(volume => {
                        const volumeRequest = new ShowVolumeRequest();
                        volumeRequest.volumeId = volume.id;
                        return evsClient.showVolume(volumeRequest)
                            .then(volumeResult => {
                       //         console.log(`DEBUG: ShowVolume response for volume ${volume.id}:`, JSON.stringify(volumeResult, null, 2));
                                return {
                                    volumeId: volume.id,
                                    encrypted: volumeResult.volume.encrypted || false
                                };
                            })
                            .catch(err => {
                                console.error(`ERROR: Failed to fetch volume ${volume.id}:`, err.message);
                                return {
                                    volumeId: volume.id,
                                    encrypted: false // Default to false if the API call fails
                                };
                            });
                    });

                    return Promise.all(diskPromises).then(diskDetails => {
                        return {
                            id: server.id,
                            name: server.name,
                            disks: diskDetails
                        };
                    });
                });

                Promise.all(serverPromises)
                    .then(serverDetails => {
                        //console.log('DEBUG: ECS instances collected:', serverDetails.length);
                        const collection = { servers: serverDetails };
                        callback(null, collection);
                    })
                    .catch(err => {
                        console.error('ERROR: Failed to process ECS instances:', err.message);
                        callback(err);
                    });
            })
            .catch(err => {
                console.error('ERROR: Failed to collect ECS instances:', err.message);
                console.error('ERROR: Full error details:', JSON.stringify(err, null, 2));
                callback(err);
            });
    } catch (err) {
        console.error('ERROR: Failed to initialize ECS/EVS clients:', err.message);
        console.error('ERROR: Full error details:', JSON.stringify(err, null, 2));
        callback(err);
    }
};
