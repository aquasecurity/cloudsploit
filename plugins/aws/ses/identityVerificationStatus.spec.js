var expect = require('chai').expect;
var identityVerificationStatus = require('./identityVerificationStatus');


const listIdentities = [
    "mujtabatarar@gmail.com",
    "sadeed1999@gmail.com",
];

const getIdentityVerificationAttributes = [
{
    "sadeed1999@gmail.com": {
        "VerificationStatus": "Success"
    },
},
{
    "mujtabatarar@gmail.com": {
        "VerificationStatus": "Pending"
    }
    
}
];

const createCache = (listIdentities, mailAttributes, listErr, getErr) => {
    return {
        ses: {
            listIdentities: {
                'us-east-1': {
                    err: listErr,
                    data: listIdentities
                }
            },
            getIdentityVerificationAttributes: {
                'us-east-1': {
                    err: getErr,
                    data: {
                        "VerificationAttributes": mailAttributes 
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


describe('identityVerificationStatus', function () {
    describe('run', function () {
        it('should PASS if Verification status is a success', function (done) {
            const cache = createCache(listIdentities[1], getIdentityVerificationAttributes[0]);
            identityVerificationStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Verification status is a success');
                done();
            });
        });

        it('should FAIL if Verification status is not a success', function (done) {
            const cache = createCache(listIdentities[0], getIdentityVerificationAttributes[1]);
            identityVerificationStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Verification status is not a success');
                done();
            });
        });

        it('should PASS if no SES identities found', function (done) {
            const cache = createCache([]);
            identityVerificationStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SES identities found');
                done();
            });
        });

        it('should UNKNOWN if Unable to list SES identities', function (done) {
            const cache = createCache([], {}, { message: 'error listing identities'});
            identityVerificationStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list SES identities');
                done();
            });
        });

        it('should UNKNOWN if Unable to get SES Verification attributes', function (done) {
            const cache = createCache(listIdentities, {}, null, { messgage: 'error getting SES Verification attributes'});
            identityVerificationStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get SES Verification attributes');
                done();
            });
        });

        it('should not return anything if list SES identities response not found', function (done) {
            const cache = createNullCache();
            identityVerificationStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});