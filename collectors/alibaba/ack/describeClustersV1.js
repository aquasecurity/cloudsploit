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

module.exports = function(AlibabaConfig, collection, region, callback) {
    let localConfig = {...AlibabaConfig};
    localConfig['endpoint'] = `https://cs.${region}.aliyuncs.com`;
    localConfig['apiVersion'] = apiVersion;
    var client = new ROAClient(localConfig);

    collection.ack.describeClustersV1[region].data = [];

    var execute = function() {
        var queries = {
            'RegionId': region,
            'page_size': 50,
            'page_number': pageNumber
        };
        client.request(httpMethod, uriPath, queries, body, headers, requestOption).then((res) => {
            callCB(null, res);
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
