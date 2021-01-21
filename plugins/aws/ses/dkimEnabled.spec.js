var expect = require('chai').expect;
var dkimEnabled = require('./dkimEnabled');


const listIdentities = [
    'aquasec.com'
];

const getIdentityDkimAttributes = [
    {
        "DkimEnabled": true,
        "DkimVerificationStatus": "Pending",
        "DkimTokens": [
            "otux44vv2jf7bme4j6y7qyagkni466lo",
            "tep4hxszbbu4ltdyxzpgkjqoghl7f64b",
            "ljnfv3lg7vyxvwefsarexpur4hc6sle7"
        ]
    },
    {
        "DkimEnabled": true,
        "DkimVerificationStatus": "Success",
        "DkimTokens": [
            "otux44vv2jf7bme4j6y7qyagkni466lo",
            "tep4hxszbbu4ltdyxzpgkjqoghl7f64b",
            "ljnfv3lg7vyxvwefsarexpur4hc6sle7"
        ]
    },
    {
        "DkimEnabled": false,
        "DkimVerificationStatus": "Pending",
        "DkimTokens": [
            "otux44vv2jf7bme4j6y7qyagkni466lo",
            "tep4hxszbbu4ltdyxzpgkjqoghl7f64b",
            "ljnfv3lg7vyxvwefsarexpur4hc6sle7"
        ]
    }
];

const createCache = (listIdentities, dkimAttributes, listErr, getErr) => {
    return {
        ses: {
            listIdentities: {
                'us-east-1': {
                    err: listErr,
                    data: listIdentities
                }
            },
            getIdentityDkimAttributes: {
                'us-east-1': {
                    err: getErr,
                    data: {
                        DkimAttributes: dkimAttributes
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        ses: {
            listIdentities: {
                'us-east-1': null,
            }
        }
    };
};


describe('dkimEnabled', function () {
    describe('run', function () {
        it('should PASS if DKIM is enabled and configured properly', function (done) {
            const cache = createCache(listIdentities, [getIdentityDkimAttributes[1]]);
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if DKIM is not enabled', function (done) {
            const cache = createCache(listIdentities, [getIdentityDkimAttributes[2]]);
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should WARN if DKIM is enabled, but not configured properly', function (done) {
            const cache = createCache(listIdentities, [getIdentityDkimAttributes[0]]);
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no SES identities found', function (done) {
            const cache = createCache([]);
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for SES identities', function (done) {
            const cache = createCache([], {}, { message: 'error listing identities'});
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if Unable to get SES DKIM attributes', function (done) {
            const cache = createCache(listIdentities, {}, null, { messgage: 'error getting SES DKIM attributes'});
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list SES identities response not found', function (done) {
            const cache = createNullCache();
            dkimEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});