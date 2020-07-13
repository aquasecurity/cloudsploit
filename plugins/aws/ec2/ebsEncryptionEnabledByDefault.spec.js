var expect = require('chai').expect;
var ebsEncryptionEnabledByDefault = require('./ebsEncryptionEnabledByDefault')

const createCache = (boolValue) => {
    return {
        ec2: {
            getEbsEncryptionByDefault: {
                'us-east-1': {
                    data: boolValue
                },
            },
        },
    };
};

describe('ebsEncryptionEnabledByDefault', function () {
    describe('run', function () {
        it('should FAIL if ebs encryption by default is disabled', function (done) {
            const cache = createCache(false);
            const settings = {};

            ebsEncryptionEnabledByDefault.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done()
            });
        });

        it('should PASS if ebs encryption by default is enabled', function (done) {
            const cache = createCache(true);
            const settings = {};

            ebsEncryptionEnabledByDefault.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
