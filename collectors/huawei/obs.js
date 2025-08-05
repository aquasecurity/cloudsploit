'use strict';

const ObsClient = require('esdk-obs-nodejs');

module.exports = async function(cloudConfig, callback) {
    const server = `https://obs.${cloudConfig.endpoint.split('.')[1]}.myhuaweicloud.com`;
    //console.log('DEBUG: OBS endpoint:', server);
    const obsClient = new ObsClient({
        access_key_id: cloudConfig.accessKeyId,
        secret_access_key: cloudConfig.secretAccessKey,
        server: server
    });

    try {
        const listResult = await obsClient.listBuckets();
        //console.log('DEBUG: Raw listBuckets response:', JSON.stringify(listResult, null, 2));
        const buckets = listResult.InterfaceResult.Buckets || [];
        const bucketDetails = await Promise.all(buckets.map(async (bucket) => {
            const aclResult = await obsClient.getBucketAcl({ Bucket: bucket.BucketName });
           // console.log(`DEBUG: Raw getBucketAcl response for ${bucket.BucketName}:`, JSON.stringify(aclResult, null, 2));
            let encryption = null;
            try {
                const encryptionResult = await obsClient.getBucketEncryption({ Bucket: bucket.BucketName });
                //console.log(`DEBUG: Raw getBucketEncryption response for ${bucket.BucketName}:`, JSON.stringify(encryptionResult, null, 2));
                encryption = encryptionResult.InterfaceResult || null;
            } catch (err) {
                //console.log(`DEBUG: No encryption set for ${bucket.BucketName}:`, err.message);
            }
            return {
                name: bucket.BucketName,
                creationDate: bucket.CreationDate,
                acl: aclResult.InterfaceResult.Grants || [],
                encryption: encryption
            };
        }));

        const collection = { buckets: bucketDetails };
        callback(null, collection);
    } catch (err) {
        console.error('ERROR: Failed to collect OBS buckets:', err.message);
        callback(err);
    }
};
