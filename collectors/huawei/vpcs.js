'use strict';

const { VpcClient, ListVpcsRequest } = require('@huaweicloud/huaweicloud-sdk-vpc');
const { BasicCredentials } = require('@huaweicloud/huaweicloud-sdk-core');

module.exports = function(cloudConfig, callback) {
    //console.log('DEBUG: Starting VPC collection with config:', JSON.stringify(cloudConfig, null, 2));

    // Validate required config fields
    if (!cloudConfig.accessKeyId || !cloudConfig.secretAccessKey) {
        const err = new Error('Missing accessKeyId or secretAccessKey in cloudConfig');
        console.error('ERROR: VPC collector validation failed:', err.message);
        return callback(err);
    }

    try {
        // Initialize credentials
        const credentials = new BasicCredentials()
            .withAk(cloudConfig.accessKeyId)
            .withSk(cloudConfig.secretAccessKey)
            .withProjectId(cloudConfig.projectId || '');

        // Create the VPC client using the builder pattern
        const endpoint = `https://vpc.${cloudConfig.region}.myhuaweicloud.com`;
      //  console.log('DEBUG: Using VPC endpoint:', endpoint);
        const client = VpcClient.newBuilder()
            .withCredential(credentials)
            .withEndpoint(endpoint)
            .build();

        // Create the request for ListVpcs
        //console.log('DEBUG: Calling ListVpcs API...');
        const request = new ListVpcsRequest();
        client.listVpcs(request)
            .then(listVpcsResult => {
          //      console.log('DEBUG: Raw listVpcs response:', JSON.stringify(listVpcsResult, null, 2));

                const vpcs = listVpcsResult.vpcs || [];
            //    console.log('DEBUG: Found', vpcs.length, 'VPCs');

                const vpcDetails = vpcs.map(vpc => ({
                    id: vpc.id,
                    name: vpc.name,
                    cidr: vpc.cidr,
                    status: vpc.status,
                    enable_flow_log: vpc.enable_flow_log || false // For vpcFlowLogsEnabled plugin
                }));

              //  console.log('DEBUG: VPCs collected:', vpcDetails.length);
                const collection = { vpcs: vpcDetails };
                callback(null, collection);
            })
            .catch(err => {
                console.error('ERROR: Failed to collect VPCs:', err.message);
                console.error('ERROR: Full error details:', JSON.stringify(err, null, 2));
                callback(err);
            });
    } catch (err) {
        console.error('ERROR: Failed to initialize VPC client:', err.message);
        console.error('ERROR: Full error details:', JSON.stringify(err, null, 2));
        callback(err);
    }
};
