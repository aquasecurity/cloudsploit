var async = require('async');
var helpers = require('../../helpers');

// this are the avliable service found from
//https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/KMS.html#listAliases-property
var services = [
    'dynamodb:void(0)',
    'ebs:void(0)',
    'elasticfilesystem:void(0)',
    'es:void(0)',
    'kinesisvideo:void(0)',
    'RDS:describeDBInstances',
    'redshift:void(0)',
    's3:void(0)',
    'ssm:void(0)',
    //'RDS:describeDBInstances'
]
//var regex = '^Default master key.*$'
var regex = 'Default master key that protects my (.*)'

module.exports = {
    title: 'KMS Default Key Usage',
    category: 'KMS',
    description: 'Checks various services to ensure the default KMS key is not being used',
    more_info: 'It is recommended not to use the default key to avoid encrypting \
        disparate sets of data with the same key. Each application should have its \
        own customer-managed KMS key.',
    recommended_action: 'Avoid using the default KMS key',
    link: 'http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html',
    apis: ['KMS:listKeys', 'KMS:describeKey'].concat(services),

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.kms, function(region, rcb){
            var listKeys = helpers.addSource(cache, source,
                    ['kms', 'listKeys', region]);
            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            if (!listKeys.data.length) {
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();
            }

            // var describeDBInstances = helpers.addSource(cache, source,
            //     ['rds', 'describeDBInstances', region]);
            // debugger;
            var default_keys = [];

            async.each(listKeys.data, function(kmsKey, kcb){
                var describeKey = helpers.addSource(cache, source,
                    ['kms', 'describeKey', region, kmsKey.KeyId]);
                if (describeKey.data.KeyMetadata.Description.match(regex)) {
                    res = describeKey.data.KeyMetadata.Description.match(regex)
                    service = res[1].split(' ')[0]
                    default_keys.push(service+'##'+describeKey.data.KeyMetadata.KeyId);
                }

                // if any default key found then check for that service
                for(key of default_keys){
                    for(ser of services){
                        if (ser.split(':')[0].toLowerCase()==key.split('##')[0].toLowerCase()){

                            var ser_results = helpers.addSource(cache, source,
                                [ser.split(':')[0].toLowerCase(), ser.split(':')[1], region]);
                            // used for rds and tested
                            for(res of ser_results.data){
                                if ((res.StorageEncrypted) && key.split("##")[1].indexOf(res.KmsKeyId)){
                                    msgs = ser.split(':')[0] + ' using default key'
                                    helpers.addResult(results, 2, msgs, region, res.KmsKeyId);
                                }
                            }
                        }
                    }

                }

                kcb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};