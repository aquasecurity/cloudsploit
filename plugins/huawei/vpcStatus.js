module.exports = {
    title: 'Huawei VPC Status',
    category: 'VPC',
    description: 'Verifies that VPCs are in an active and healthy state.',
    apis: ['ListVpcs'],
    check: function(collection, callback) {
        const results = [];

        if (!collection.vpcs || !collection.vpcs.vpcs || !collection.vpcs.vpcs.length) {
            results.push({
                resource: 'N/A',
                region: 'global',
                status: 0,
                message: 'No VPCs found'
            });
        } else {
            collection.vpcs.vpcs.forEach(vpc => {
                const isHealthy = vpc.status === 'OK';
                results.push({
                    resource: vpc.id,
                    region: 'global',
                    status: isHealthy ? 0 : 2,
                    message: isHealthy ? 'VPC is in a healthy state' : 'VPC is not in a healthy state'
                });
            });
        }

        callback(null, results);
    }
};
