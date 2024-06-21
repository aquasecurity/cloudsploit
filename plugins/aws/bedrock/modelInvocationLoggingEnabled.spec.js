var expect = require('chai').expect;
var modelInvocationLoggingEnabled = require('./modelInvocationLoggingEnabled');

const invocationLoggingConfiguration = {
    "loggingConfig": {
        "s3Config": {
            "bucketName": "bedrockbuckettest",
            "keyPrefix": ""
        },
        "textDataDeliveryEnabled": true,
        "imageDataDeliveryEnabled": true,
        "embeddingDataDeliveryEnabled": true
    }
}

const createCache = (invocationLoggingConfiguration, invocationLoggingConfigurationErr) => {
    return {
        bedrock: {
            getModelInvocationLoggingConfiguration: {
                'us-east-1': {
                    err: invocationLoggingConfigurationErr,
                    data: invocationLoggingConfiguration
                },
            },
        }
    };
};

describe('modelInvocationLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if model invocation logging is enabled for bedrock models', function (done) {
            const cache = createCache(invocationLoggingConfiguration);
            modelInvocationLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if model invocation logging is disabled for bedrock models', function (done) {
            const cache = createCache();
            modelInvocationLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for model invocation logging', function (done) {
            const cache = createCache(null, { message: "Unable to list model invocation logging config"});
            modelInvocationLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
     });
})