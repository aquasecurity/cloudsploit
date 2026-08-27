var expect = require('chai').expect;
var securityDefaultsEnabled = require('./securityDefaultsEnabled.js');

const policies = [
    {
        "id": "00000000-0000-0000-0000-000000000005",
        "displayName": "Security Defaults",
        "description": "Security defaults is a set of basic identity security mechanisms recommended by Microsoft.",
        "isEnabled": true
    },
    {
        "id": "00000000-0000-0000-0000-000000000005",
        "displayName": "Security Defaults",
        "description": "Security defaults is a set of basic identity security mechanisms recommended by Microsoft.",
        "isEnabled": false
    }
];

const createCache = (policy, err) => {
    return {
        securityDefaultsPolicy: {
            get: {
                'global': {
                    data: policy,
                    err: err
                }
            }
        }
    };
};

describe('securityDefaultsEnabled', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for security defaults policy', function (done) {
            const cache = createCache(null, ['error']);
            securityDefaultsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security defaults policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no security defaults policy found', function (done) {
            const cache = createCache([], null);
            securityDefaultsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing security defaults policy found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if security defaults are enabled', function (done) {
            const cache = createCache([policies[0]], null);
            securityDefaultsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security defaults are enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if security defaults are not enabled', function (done) {
            const cache = createCache([policies[1]], null);
            securityDefaultsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security defaults are not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
