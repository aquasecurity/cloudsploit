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
    remediation_description: 'Encryption for the affected Kinesis streams will be enabled.',
    remediation_min_version: '202010301919',
    apis_remediate: ['Kinesis:listStreams', 'Kinesis:describeStream'],
    remediation_inputs: {
        kmsKeyIdforKinesis: {
            name: '(Optional) KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    actions: {
        remediate: ['Kinesis:startStreamEncryption'],
        rollback: ['Kinesis:stopStreamEncryption']
    },
    permissions: {
        remediate: ['kinesis:StartStreamEncryption'],
        rollback: ['kinesis:StopStreamEncryption']
    },
    realtime_triggers: ['kinesis:CreateStream', 'kinesis:StopStreamEncryption'],

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
                
                var streamArn = describeStream.data.StreamDescription.StreamARN;

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
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'kinesisEncrypted';
        var streamNameArr = resource.split(':');
        var streamName = streamNameArr[streamNameArr.length - 1].split('/');
        streamName = streamName[streamName.length - 1];
        // find the location of the Kinesis Stream needing to be remediated
        var streamLocation = streamNameArr[3];
        var err;
        if (!streamLocation) {
            err = 'Unable to get stream location';
            return callback(err, null);
        }
        // add the location of the Kinesis Stream to the config
        config.region = streamLocation;
        var params = {};
        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforKinesis) {
            params = {
                EncryptionType: 'KMS', /* required */
                KeyId: settings.input.kmsKeyIdforKinesis, /* required */
                StreamName: streamName /* required */
            };
        } else {
            params = {
                EncryptionType: 'KMS', /* required */
                KeyId: defaultKmsKey, /* required */
                StreamName: streamName /* required */
            };
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
            'KinesisStream': streamName
        };

        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'ENCRYPTED',
                'KinesisStream': streamName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },

    rollback: function(config, cache, settings, resource, callback) {
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }
};