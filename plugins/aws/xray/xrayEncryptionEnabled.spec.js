var assert = require('assert');
var expect = require('chai').expect;
var xrayEncryptionEnabled = require('./xrayEncryptionEnabled')

const createCache = (data) => {
    return {
        xray: {
            getEncryptionConfig: {
                'us-east-1': {
                    data: data
                }
            }
        }
    };
};

describe('xrayEncryptionEnabled', function () {
    describe('run', function () {
        it('should FAIL if there is no regional data', function (done) {
            const cache = createCache({});
            xrayEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if xray encryption is using NONE type', function (done) {
            const cache = createCache({
                Type: 'NONE'
            });
            xrayEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if xray encryption is using KMS type without a KeyId', function (done) {
            const cache = createCache({
                Type: 'KMS'
            });
            xrayEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if xray encryption is using KMS type', function (done) {
            const cache = createCache({
                Type: 'KMS',
                KeyId: 'my-key'
            });
            xrayEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
