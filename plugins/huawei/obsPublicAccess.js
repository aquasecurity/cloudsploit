module.exports = {
    title: 'Huawei OBS Bucket Public Access',
    category: 'OBS',
    description: 'Checks if OBS buckets allow public access via ACLs.',
    apis: ['ListBuckets'],
    check: function(collection, callback) {
        //console.log('DEBUG: obsPublicAccess plugin called with collection:', JSON.stringify(collection, null, 2));
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
                const hasPublicAccess = bucket.acl.some(grant => 
                    grant.Grantee && grant.Grantee.URI === 'Everyone' && 
                    (grant.Permission === 'READ' || grant.Permission === 'WRITE')
                );
                results.push({
                    resource: bucket.name,
                    region: 'global',
                    status: hasPublicAccess ? 2 : 0, // 2 = FAIL, 0 = PASS
                    message: hasPublicAccess ? 'OBS bucket allows public access' : 'OBS bucket does not allow public access'
                });
            });
        }

        //console.log('DEBUG: obsPublicAccess results:', results);
        callback(null, results);
    }
};
