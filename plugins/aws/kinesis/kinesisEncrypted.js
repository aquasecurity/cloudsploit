var async = require('async');
var helpers = require('../../../helpers/aws');

var defaultKmsKey = 'alias/aws/kinesis';

module.exports = {
    title: 'Kinesis Streams Encrypted',
    category: 'Kinesis',
    description: 'Ensures Kinesis Streams encryption is enabled',
    more_info: 'Data sent to Kinesis Streams can be encrypted using KMS server-side encryption. Existing streams can be modified to add encryption with minimal overhead.',
    recommended_action: 'Enable encryption using KMS for all Kinesis Streams.',
    link: 'https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html',
    apis: ['Kinesis:listStreams', 'Kinesis:describeStream'],
    compliance: {
        hipaa: 'Kinesis encryption must be used when processing any HIPAA-related data. ' +
                'AWS KMS encryption ensures that the Kinesis message payload meets the ' +
                'encryption in transit and at rest requirements of HIPAA.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.kinesis, function(region, rcb){
            var listStreams = helpers.addSource(cache, source,
                ['kinesis', 'listStreams', region]);

            if (!listStreams) return rcb();

            if (listStreams.err) {
                helpers.addResult(results, 3,
                    'Unable to query for Kinesis streams: ' + helpers.addError(listStreams), region);
                return rcb();
            }

            if (!listStreams.data || !listStreams.data.length) {
                helpers.addResult(results, 0, 'No Kinesis streams found', region);
                return rcb();
            }

            async.each(listStreams.data, function(stream, cb){

                var describeStream = helpers.addSource(cache, source,
                    ['kinesis', 'describeStream', region, stream]);

                if (!describeStream ||
                    (!describeStream.err && !describeStream.data)) {
                    return cb();
                }

                if (describeStream.err || !describeStream.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Kinesis for stream: ' + stream + ': ' + helpers.addError(describeStream),
                        region);
                    return cb();
                }

                if (!describeStream.data.StreamDescription) {
                    helpers.addResult(results, 3,
                        'Unable to query Kinesis for stream: ' + stream + ': no stream data',
                        region);
                    return cb();
                }
                
                var streamArn = describeStream.data.StreamDescription.StreamArn;

                if (describeStream.data.StreamDescription.KeyId) {
                    if (describeStream.data.StreamDescription.KeyId === defaultKmsKey) {
                        helpers.addResult(results, 1,
                            'The Kinesis stream uses the default KMS key (' + defaultKmsKey + ') for SSE',
                            region, streamArn);
                    } else {
                        helpers.addResult(results, 0,
                            'The Kinesis stream uses a KMS key for SSE',
                            region, streamArn);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'The Kinesis stream does not use a KMS key for SSE',
                        region, streamArn);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};

