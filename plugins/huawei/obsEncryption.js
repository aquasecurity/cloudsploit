module.exports = {
    title: 'Huawei OBS Bucket Encryption',
    category: 'OBS',
    description: 'Checks if OBS buckets have server-side encryption enabled.',
    apis: ['ListBuckets'],
    check: function(collection, callback) {
        //console.log('DEBUG: obsEncryption plugin called with collection:', JSON.stringify(collection, null, 2));
        const results = [];

        if (!collection.obs || !collection.obs.buckets || !collection.obs.buckets.length) {
            results.push({
                resource: 'N/A',
                region: 'global',
                status: 0,
                message: 'No OBS buckets found'
            });
        } else {
            collection.obs.buckets.forEach(bucket => {
                const encryptionEnabled = bucket.encryption !== null && bucket.encryption !== undefined;
                results.push({
                    resource: bucket.name,
                    region: 'global',
                    status: encryptionEnabled ? 0 : 2, // 0 = PASS, 2 = FAIL
                    message: encryptionEnabled ? 'OBS bucket has server-side encryption enabled' : 'OBS bucket does not have server-side encryption enabled'
                });
            });
        }

        //console.log('DEBUG: obsEncryption results:', results);
        callback(null, results);
    }
};
