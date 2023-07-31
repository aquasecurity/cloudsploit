var ROAClient = require('@alicloud/pop-core').ROAClient;

var apiVersion = '2015-12-15';
var httpMethod = 'GET';
var uriPath = '/api/v1/clusters';
var body = '{}';
var headers = {
    'Content-Type': 'application/json'
};
var requestOption = {};
var pageNumber = 1;

// Function to describeDetailCluster
function describeDetailCluster(AlibabaConfig, collection, region, clusterId, callback) {
    let localConfig = { ...AlibabaConfig };
    localConfig['endpoint'] = `https://cs.${region}.aliyuncs.com`;
    localConfig['apiVersion'] = apiVersion;
    var client = new ROAClient(localConfig);

    var uriPath = `/api/v1/clusters/${clusterId}`;
    var httpMethod ='GET';
    var body = '{}';
    var headers = {
        'Content-Type': 'application/json'
    };
    var requestOption = {};

    client.request(httpMethod, uriPath, {}, body, headers, requestOption).then((res) => {
        // Assuming the response data contains the cluster details, you can handle it accordingly.
        callCB(null, res);
    }, (err) => {
        callCB(err);
    });

    var callCB = function(err, data) {
        if (err) {
            collection.ack.describeDetailCluster[region].err = err;
            return callback();
        }
        // Assuming you want to store the detail data for each cluster by clusterId
        collection.ack.describeDetailCluster[region].data[clusterId] = data;
        return callback();
    };
}

module.exports = function(AlibabaConfig, collection, region, callback) {
    let localConfig = { ...AlibabaConfig };
    localConfig['endpoint'] = `https://cs.${region}.aliyuncs.com`;
    localConfig['apiVersion'] = apiVersion;
    var client = new ROAClient(localConfig);

    collection.ack.describeClustersV1[region].data = [];
    collection.ack.describeDetailCluster[region].data = []; // Initialize an empty object to store detail data for each cluster.

    var execute = function() {
        var queries = {
            'RegionId': region,
            'page_size': 50,
            'page_number': pageNumber
        };
        client.request(httpMethod, uriPath, queries, body, headers, requestOption).then((res) => {
            // Assuming the response data contains a list of clusters, each with a unique cluster_id
            // Loop through the list and call describeDetailCluster for each cluster.
            var promises = res.clusters.map(cluster => {
                return describeDetailCluster(AlibabaConfig, collection, region, cluster.cluster_id, () => {});
            });
            // Wait for all describeDetailCluster calls to finish before calling the callback.
            Promise.all(promises).then(() => {
                callCB(null, res);
            }).catch(err => {
                callCB(err);
            });
        }, (err) => {
            callCB(err);
        });
    };

    var callCB = function(err, data) {
        if (err) {
            collection.ack.describeClustersV1[region].err = err;
            return callback();
        }
        collection.ack.describeClustersV1[region].data = collection.ack.describeClustersV1[region].data.concat(data.clusters);
        if (data['page_info'] && data['page_info']['page_size'] &&
            data['page_info']['page_number'] &&data['page_info']['total_count'] &&
            (data['page_info']['page_size'] * data['page_info']['page_number']) < data['page_info']['total_count']){
            pageNumber += 1;
            execute();
        } else return callback();
    };

    execute();
};
