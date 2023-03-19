const expect = require('chai').expect;
var collectionCmkEncrypted = require('./collectionCmkEncrypted');

const listCollections = [
    {
       "arn": 'arn:aws:aoss:us-east-1:000011112222:collection:testing-123',
       "id": "123xyz",
       "name": "test",
       "status": "ACTIVE"
    },
];
const listSecurityPolicies =[
    {
        "name": "auto-test",
        "type": "encryption",
    }
]

const getSecurityPolicy = [
    
    {
        securityPolicyDetail: {
            createdDate: 1677926608534,
            description: 'testPolicy',
            lastModifiedDate: 1677926608534,
            name: 'auto-test',
            policy: { Rules: [{ Resource:["collection/test"], ResourceType:'collection' }], AWSOwnedKey: true },
            policyVersion: 'MTY3NzkyNjYwODUzNF8x',
            type: 'encryption'
        }
    },
    {
        securityPolicyDetail: {
            createdDate: 1677926608534,
            description: 'testPolicy',
            lastModifiedDate: 1677926608534,
            name: 'auto-test',
            policy: { Rules: [{ Resource:["collection/temp"], ResourceType:'collection' }], KmsARN: 'arn:aws:kms:us-east-1:000011112222:key/test-key'},
            policyVersion: 'MTY3NzkyNjYwODUzNF8x',
            type: 'network'
        }
    }
]

const createCache = (listCollections, listSecurityPolicies, getSecurityPolicy) => {
    return {
        opensearchserverless: {
            listCollections: {
                'us-east-1': {
                    data: listCollections
                }
            },
            listSecurityPolicies: {
                'us-east-1': {
                    data: listSecurityPolicies               
                }
            },
            getEncryptionSecurityPolicy: {
                'us-east-1': {
                    "auto-test":{
                        data: getSecurityPolicy
                    }
                }
            }
        }
    };
};

describe('collectionCmkEncrypted', function () {
    describe('run', function () {

        it('should give Unknown result if unable to list collections', function (done) {
            const cache = createCache(null);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query list collections');
                done();
            });
        });

        it('should Pass if no collection found', function (done) {
            const cache = createCache([]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Collection found');
                done();
            });
        });

        it('should give UNKNOWN result if unable to list security Policies', function (done) {
            const cache = createCache(listCollections, null);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query list security policy');
                done();
            });
        });

        it('should PASS if no security policy found', function (done) {
            const cache = createCache(listCollections, []);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Security Policy found');
                done();
            });
        });
        it('should give UNKNOWN result if unable to query get security policy', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, null);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query get security policy');
                done();
            });
        });
        it('should PASS if collection is publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[0]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenSearch Serverless collection is using default key for encryption');
                done();
            });
        });
        it('should FAIL if collection is not publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[1]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenSearch Serverless collection is using CMK for encryption');
                done();
            });
        });

    });
});